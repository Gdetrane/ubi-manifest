import logging
from collections import defaultdict
from concurrent.futures import Future
from typing import List, Set

from more_executors.futures import f_proxy
from pubtools.pulplib import (
    Client,
    Criteria,
    ModulemdDefaultsUnit,
    ModulemdUnit,
    RpmUnit,
    YumRepository,
)
from pydantic import BaseModel, ConfigDict

from ubi_manifest.worker.common import filter_whitelist
from ubi_manifest.worker.models import PackageToExclude, UbiUnit
from ubi_manifest.worker.pulp_queries import MODULEMD_FIELDS, search_units
from ubi_manifest.worker.tasks.celery import app
from ubi_manifest.worker.ubi_config import (
    UbiConfigLoader,
    get_content_config,
)
from ubi_manifest.worker.utils import (
    RELATION_CMP_MAP,
    create_or_criteria,
    is_blacklisted,
    keep_n_latest_rpms,
    make_pulp_client,
    parse_blacklist_config,
)

_LOG = logging.getLogger(__name__)

RPM_FIELDS = ["name", "version", "release", "arch", "filename"]
MD_FIELDS = ["name", "stream", "version", "context", "arch"]


class RepoContent(BaseModel):
    """Represents the content of a repository for auditing purposes.

    Attributes:
        rpms (Set[UbiUnit]): A set of RPM units present in the repository.
        whitelist (Set[str]): A set of package names that are whitelisted.
        blacklist (Set[PackageToExclude]): A set of packages that are excluded or blacklisted.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)
    rpms: Set[UbiUnit]
    modular_rpms: Set[UbiUnit]
    modulardfs_rpms: Set[UbiUnit]
    whitelist: Set[str]
    blacklist: Set[PackageToExclude]


class ContentComparator:
    """Compares versions of RPM units and tracks seen RPMs for a specific repository.

    Attributes:
        repo_id (str): The ID of the repository being audited.
        seen_rpms (Set[UbiUnit]): A set of RPM units that have been processed during the comparison.

    Methods:
        compare_versions(out_unit: UbiUnit, in_unit: UbiUnit) -> None:
            Compares the versions of two RPM units and logs a warning if
            the input unit is more recent than the output unit.
    """

    def __init__(self, repo_id: str):
        self.repo_id = repo_id
        self.seen_rpms: Set[UbiUnit] = set()

    def compare_versions(self, out_unit: UbiUnit, in_unit: UbiUnit) -> None:
        """Compare versions of RPM units and log outdated versions."""
        out_evr = (out_unit.epoch, out_unit.version, out_unit.release)
        in_evr = (in_unit.epoch, in_unit.version, in_unit.release)

        if RELATION_CMP_MAP["LT"](out_evr, in_evr):  # type: ignore
            _LOG.warning(
                "[%s] UBI rpm '%s' version is outdated (current: %s, latest: %s)",
                self.repo_id,
                out_unit.name,
                out_evr,
                in_evr,
            )


class ContentAuditor:
    """Audits the content of a repository by fetching, processing, and comparing RPM units.

    Attributes:
        client (Client): The client used to interact with the repository.
        out_repo (YumRepository): The output repository being audited.
        config_loader (UbiConfigLoader): A configuration loader
        comparator (ContentComparator): An instance of ContentComparator for comparing RPM versions.
        repo_content (RepoContent): An instance of RepoContent holding the repository's content.

    Methods:
        audit() -> None:
            Main workflow for auditing the repository content.
        _fetch_output_content() -> None:
            Fetches and stores the output repository content.
        _process_input_repos() -> None:
            Processes all input repositories and accumulates data for auditing.
        _accumulate_repo_data(in_repo: YumRepository) -> None:
            Accumulates whitelist and blacklist data from the repository configuration.
        _process_input_rpms(in_repo: YumRepository) -> None:
            Processes and compares input RPMs with output content.
        _get_input_rpm_criteria() -> List[Criteria]:
            Generates criteria for searching input RPMs.
        _compare_rpm_content(future: Future[Set[UbiUnit]]) -> None:
            Compares input RPMs with output RPMs using the ContentComparator.
        _get_latest_input_rpms(future: Future[Set[UbiUnit]]) -> List[UbiUnit]:
            Retrieves the latest RPM versions from input repositories.
        _verify_content_rules() -> None:
            Verifies blacklist and whitelist rules and logs any violations.
        _check_blacklist_violations() -> None:
            Checks for the presence of blacklisted packages.
        _check_whitelist_compliance() -> None:
            Checks for missing packages in the whitelist.
    """

    def __init__(
        self,
        client: Client,
        out_repo: YumRepository,
        config_loader: UbiConfigLoader,
    ) -> None:
        self.client = client
        self.out_repo = out_repo
        self.config_loader = config_loader
        self.comparator = ContentComparator(out_repo.id)
        self.repo_content = RepoContent(
            rpms=set(),
            modular_rpms=set(),
            modulardfs_rpms=set(),
            whitelist=set(),
            blacklist=set(),
        )
        self.input_rpms: Set[UbiUnit] = set()

    def audit(self) -> None:
        """Main auditing workflow, wrapping a sequence of auditing steps."""
        self._fetch_output_content()
        self._process_input_repos()
        self._verify_content_rules()

    def _fetch_output_content(self) -> None:
        """Fetch and store output repository content for the auditor."""
        future_rpms = search_units(
            self.out_repo, [Criteria.true()], RpmUnit, unit_fields=RPM_FIELDS
        )
        future_modular_rpms = search_units(
            self.out_repo, [Criteria.true()], ModulemdUnit, unit_fields=MODULEMD_FIELDS
        )
        future_modulardfs_rpms = search_units(
            self.out_repo, [Criteria.true()], ModulemdDefaultsUnit
        )
        self.repo_content.rpms = f_proxy(future_rpms).result()
        self.repo_content.modular_rpms = f_proxy(future_modular_rpms).result()
        self.repo_content.modulardfs_rpms = f_proxy(future_modulardfs_rpms).result()

    def _process_input_repos(self) -> None:
        """Process all input repositories and accumulate data for the auditor."""
        in_repos = self.client.search_repository(
            Criteria.with_id(self.out_repo.population_sources)
        )

        for in_repo in in_repos.result():
            self._accumulate_repo_data(in_repo)
            self._process_input_rpms(in_repo)

    def _accumulate_repo_data(self, in_repo: YumRepository) -> None:
        """Accumulate whitelist/blacklist data from repo configuration."""
        config = get_content_config(
            self.config_loader,
            in_repo.content_set,
            self.out_repo.content_set,
            self.out_repo.ubi_config_version,
        )
        self.repo_content.blacklist |= set(parse_blacklist_config(config))
        pkg_whitelist, debuginfo_whitelist = filter_whitelist(
            config, list(self.repo_content.blacklist)
        )

        self.repo_content.whitelist |= pkg_whitelist
        if "debug" in self.out_repo.id:
            self.repo_content.whitelist |= debuginfo_whitelist

    def _process_input_rpms(self, in_repo: YumRepository) -> None:
        """Process and compare input RPMs with output content."""
        criteria = self._get_input_rpm_criteria()
        future = search_units(in_repo, criteria, RpmUnit, None, RPM_FIELDS)

        self.input_rpms |= f_proxy(future).result()

        self._compare_rpm_content(future)

    def _get_input_rpm_criteria(self) -> List[Criteria]:
        """Generate criteria for searching input RPMs."""
        fields = ["name", "arch"]
        values = [(rpm.name, rpm.arch) for rpm in self.repo_content.rpms]
        return create_or_criteria(fields, values)

    def _compare_rpm_content(self, future: Future[Set[UbiUnit]]) -> None:
        """Compare input RPMs with output RPMs, using the ContentComparator class."""
        out_rpm_map = {(rpm.name, rpm.arch): rpm for rpm in self.repo_content.rpms}

        for in_rpm in self._get_latest_input_rpms(future):
            if (in_rpm.name, in_rpm.arch) in out_rpm_map:
                out_rpm = out_rpm_map[(in_rpm.name, in_rpm.arch)]
                self.comparator.compare_versions(out_rpm, in_rpm)
                self.comparator.seen_rpms.add(in_rpm)
                self.repo_content.rpms.discard(out_rpm)

    def _get_latest_input_rpms(self, future: Future[Set[UbiUnit]]) -> List[UbiUnit]:
        """Get latest RPM versions from input repositories."""
        rpm_map = defaultdict(list)
        for rpm in future.result():
            rpm_map[f"{rpm.name}_{rpm.arch}"].append(rpm)
        latest_rpms = []
        for rpm_group in rpm_map.values():
            keep_n_latest_rpms(rpm_group)
            latest_rpms.extend(rpm_group)

        return latest_rpms

    def _verify_content_rules(self) -> None:
        """Verify blacklist/whitelist rules and log any missing
        whitelisted packages or presence of blacklisted ones."""
        self._check_blacklist_violations()
        self._check_whitelist_compliance()

    def _check_blacklist_violations(self) -> None:
        """Check for presence of blacklisted packages."""
        blacklisted = {
            u.name
            for u in self.comparator.seen_rpms
            if is_blacklisted(u, list(self.repo_content.blacklist))
        }

        if blacklisted:
            _LOG.warning(
                "[%s] blacklisted content found in input repositories;\n\t%s",
                self.out_repo.id,
                "\n\t".join(sorted(blacklisted)),
            )

    def _check_whitelist_compliance(self) -> None:
        """Check for missing packages in whitelist."""
        seen_names = {u.name for u in self.comparator.seen_rpms}
        remaining_whitelist = self.repo_content.whitelist - seen_names

        if remaining_whitelist:
            _LOG.warning(
                "[%s] whitelisted content missing from UBI and/or population sources;\n\t%s",
                self.out_repo.id,
                "\n\t".join(sorted(remaining_whitelist)),
            )
            for pkg_name in remaining_whitelist:
                self._check_whitelist_package(pkg_name)

    def _check_whitelist_package(self, pkg_name: str) -> None:
        """Check a single whitelisted package against the input and output repos."""
        if self._is_modular(pkg_name):
            return  # ignoring auditing for modular content

        # check if the package name is either in in_repos or out_repos
        in_input_repos = any(rpm.name == pkg_name for rpm in self.input_rpms)
        in_output_repo = any(rpm.name == pkg_name for rpm in self.repo_content.rpms)

        if not in_input_repos and not in_output_repo:
            # this case is ok
            _LOG.info(
                "[%s] Whitelisted package '%s' not found in any input or output repositories.",
                self.out_repo.id,
                pkg_name,
            )
        elif not in_input_repos and in_output_repo:
            # whitelisted package is only in one place, not good
            _LOG.warning(
                "[%s] Whitelisted package '%s' found in out repo but not in any input repos!",
                self.out_repo.id,
                pkg_name,
            )

        elif in_input_repos and not in_output_repo:
            # whitelisted package is only in one place, not good
            _LOG.warning(
                "[%s] Whitelisted package '%s' found in input repositories but not in output repo!",
                self.out_repo.id,
                pkg_name,
            )
        elif in_input_repos and in_output_repo:
            # in both sets, so versions should be compared

            # let's get the latest rpm for input and output
            input_rpms = [
                rpm for rpm in self.input_rpms if rpm.name == pkg_name
            ]  # filtered
            output_rpms = [
                rpm for rpm in self.repo_content.rpms if rpm.name == pkg_name
            ]

            latest_input_rpm = sorted(
                input_rpms,
                key=lambda rpm: (rpm.epoch, rpm.version, rpm.release),
                reverse=True,
            )[0]
            latest_output_rpm = sorted(
                output_rpms,
                key=lambda rpm: (rpm.epoch, rpm.version, rpm.release),
                reverse=True,
            )[0]

            self.comparator.compare_versions(latest_output_rpm, latest_input_rpm)

            # also implement recursive check on dependencies (?)

    def _is_modular(self, pkg_name: str) -> bool:
        """Check if a package is modular."""
        return pkg_name in self.repo_content.modular_rpms


@app.task  # type: ignore
def content_audit_task() -> None:
    """
    This task checks that all available content is up-to-date, that whitelisted
    content is present, and that blacklisted content is absent.
    """
    config_loaders_map = {
        repo_class: UbiConfigLoader(url)
        for repo_class, url in app.conf.content_config.items()
    }

    with make_pulp_client(app.conf) as client:
        for out_repo in client.search_repository(
            Criteria.with_field("ubi_population", True)
        ):
            current_loader = None
            for repo_class, loader in config_loaders_map.items():
                if repo_class in out_repo.id:
                    current_loader = loader
                    break

            if not current_loader:
                raise ValueError(
                    f"Repository {out_repo!r} is set for ubi_population but has unexpected id."
                )

            auditor = ContentAuditor(client, out_repo, current_loader)
            auditor.audit()
