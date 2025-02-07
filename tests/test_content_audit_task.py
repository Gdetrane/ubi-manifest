import logging
from unittest import mock

import pytest
from pubtools.pulplib import Distributor, RpmUnit

from ubi_manifest.worker.tasks.content_audit import content_audit_task

from .utils import MockLoader, create_and_insert_repo


def _setup_population_sources(pulp):
    ubi_repo = create_and_insert_repo(
        pulp=pulp,
        id="ubi_repo",
        population_sources=[
            "rhel_repo-1",
            "rhel_repo-2",
        ],
        ubi_population=True,
        relative_url="foo/bar/os",
        ubi_config_version="8",
        content_set="cs_rpm_out",
    )
    distributor_rhel_1 = Distributor(
        id="yum_distributor",
        type_id="yum_distributor",
        repo_id="rhel_repo-1",
        relative_url="foo/rhel-1/os",
    )
    distributor_rhel_2 = Distributor(
        id="yum_distributor",
        type_id="yum_distributor",
        repo_id="rhel_repo-2",
        relative_url="foo/rhel-2/os",
    )
    rhel_repo_1 = create_and_insert_repo(
        id=distributor_rhel_1.repo_id,
        pulp=pulp,
        content_set="cs_rpm_in",
        relative_url=distributor_rhel_1.relative_url,
        distributors=[distributor_rhel_1],
    )
    rhel_repo_2 = create_and_insert_repo(
        id=distributor_rhel_2.repo_id,
        pulp=pulp,
        content_set="cs_rpm_in",
        relative_url=distributor_rhel_2.relative_url,
        distributors=[distributor_rhel_2],
    )

    rpm_1 = RpmUnit(
        name="gcc",
        version="9.0.1",
        release="200",
        epoch="1",
        arch="x86_64",
        sourcerpm="gcc_src-1-0.src.rpm",
        filename="gcc-10.200.x86_64.rpm",
        requires=[],
        provides=[],
    )
    rpm_2 = RpmUnit(
        name="bind",
        version="10",
        release="200",
        epoch="1",
        arch="x86_64",
        sourcerpm="bind_src-1-0.src.rpm",
        filename="bind-10.200.x86_64.rpm",
        requires=[],
        provides=[],
    )
    rpm_3 = RpmUnit(
        name="httpd.src",
        version="1",
        release="2",
        arch="x86_64",
    )
    rpm_4 = RpmUnit(
        name="pkg-debuginfo.foo",
        version="1",
        release="2",
        arch="x86_64",
    )
    rpm_5 = RpmUnit(
        name="package-name-abc",
        version="1",
        release="2",
        arch="x86_64",
    )

    pulp.insert_units(rhel_repo_1, [rpm_1, rpm_3])
    pulp.insert_units(rhel_repo_2, [rpm_2, rpm_4, rpm_5])
    pulp.insert_units(ubi_repo, [rpm_1, rpm_2, rpm_3, rpm_4, rpm_5])


@pytest.mark.parametrize("debug", [False, True], ids=["bin", "debug"])
def test_content_audit_outdated(debug, pulp, caplog):
    """
    Test that a run of the content audit task completes without issue and
    reports when content is outdated.
    """

    caplog.set_level(logging.DEBUG, logger="ubi_manifest.worker.tasks.content_audit")
    _setup_population_sources(pulp)

    repo_id = "outdated_ubi_debug_repo" if debug else "outdated_ubi_repo"

    # Populate our outdated UBI repo
    ubi_repo = create_and_insert_repo(
        pulp=pulp,
        id=repo_id,
        population_sources=[
            "rhel_repo-1",
            "rhel_repo-2",
        ],
        ubi_population=True,
        relative_url="foo/bar/os",
        ubi_config_version="8",
        content_set="cs_rpm_out",
    )
    rpm_1 = RpmUnit(
        name="gcc",
        version="8.2.1",  # outdated
        release="200",
        epoch="1",
        arch="x86_64",
        sourcerpm="gcc_src-1-0.src.rpm",
        filename="gcc-10.200.x86_64.rpm",
    )
    rpm_2 = RpmUnit(
        name="bind",
        version="10",
        release="200",
        epoch="1",
        arch="x86_64",
        sourcerpm="bind_src-1-0.src.rpm",
        filename="bind-10.200.x86_64.rpm",
    )
    pulp.insert_units(
        ubi_repo,
        [rpm_1, rpm_2],
    )

    with mock.patch("ubi_manifest.worker.utils.Client") as client:
        with mock.patch("ubiconfig.get_loader", return_value=MockLoader()):
            client.return_value = pulp.client

            # should run without error
            content_audit_task()

        # should have logged warnings
        if debug:
            expected_logs = [
                "UBI rpm 'gcc' version is outdated (current: ('0', '8.2.1', '200'), latest: ('0', '9.0.1', '200'))",
                "whitelisted content missing from UBI and/or population sources;\n\tpkg-debuginfo",
            ]
        else:
            expected_logs = [
                "UBI rpm 'gcc' version is outdated (current: ('0', '8.2.1', '200'), latest: ('0', '9.0.1', '200'))",
            ]
        for msg in expected_logs:
            assert f"[{repo_id}] {msg}" in caplog.text


def test_content_audit_blacklisted(pulp, caplog):
    """
    Test that a run of the content audit task completes without issue and
    reports when content is blacklisted.
    """

    caplog.set_level(logging.DEBUG, logger="ubi_manifest.worker.tasks.content_audit")
    _setup_population_sources(pulp)

    ubi_repo = create_and_insert_repo(
        pulp=pulp,
        id="contaminated_ubi_repo",
        population_sources=[
            "rhel_repo-1",
            "rhel_repo-2",
            "bad_repo",
        ],
        ubi_population=True,
        relative_url="foo/bar/os",
        ubi_config_version="8",
        content_set="cs_rpm_out",
    )
    bad_dist = Distributor(
        id="yum_distributor",
        type_id="yum_distributor",
        repo_id="bad_repo",
        relative_url="foo/rhel-2/os",
    )
    bad_repo = create_and_insert_repo(
        id=bad_dist.repo_id,
        pulp=pulp,
        content_set="cs_rpm_in",
        relative_url=bad_dist.relative_url,
        distributors=[bad_dist],
    )
    blacklisted = RpmUnit(
        name="kernel",
        version="10",
        release="200",
        epoch="1",
        arch="x86_64",
        sourcerpm="kernel-1-0.src.rpm",
        filename="kernel-10.200.x86_64.rpm",
        requires=[],
        provides=[],
    )
    pulp.insert_units(bad_repo, [blacklisted])
    pulp.insert_units(ubi_repo, [blacklisted])

    with mock.patch("ubi_manifest.worker.utils.Client") as client:
        with mock.patch("ubiconfig.get_loader", return_value=MockLoader()):
            client.return_value = pulp.client

            # should run without error
            content_audit_task()

        # should have logged a warning
        assert (
            "[contaminated_ubi_repo] blacklisted content found in input repositories;\n\tkernel"
            in caplog.text
        )
