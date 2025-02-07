from more_executors.futures import f_proxy
from pubtools.pulplib import Criteria

from ubi_manifest.worker.common import get_pkgs_from_all_modules
from ubi_manifest.worker.tasks.auditing import ContentProcessor
from ubi_manifest.worker.tasks.celery import app
from ubi_manifest.worker.ubi_config import UbiConfigLoader
from ubi_manifest.worker.utils import make_pulp_client


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

    with make_pulp_client(app.conf) as client:  # type: ignore
        future_out_repos = client.search_repository(
            Criteria.with_field("ubi_population", True)
        )
        all_modular_filenames = get_pkgs_from_all_modules(
            f_proxy(future_out_repos).result()  # type: ignore
        )
        for out_repo in f_proxy(future_out_repos).result():
            if "debug" in out_repo.id or "source" in out_repo.id:
                is_out_modular = False
            else:
                is_out_modular = True

            current_loader = None
            for repo_class, loader in config_loaders_map.items():
                if repo_class in out_repo.id:
                    current_loader = loader
                    break

            if not current_loader:
                raise ValueError(
                    f"Repository {out_repo!r} is set for ubi_population but has unexpected id."
                )

            search_result = client.search_repository(
                Criteria.with_id(out_repo.population_sources)
            ).result()

            in_repos = []
            for result in search_result:
                in_repos.append(result)

            content_processor = ContentProcessor(
                client,
                out_repo,
                in_repos,
                current_loader,
                all_modular_filenames,
                is_out_modular,
            )
            content_processor.process_and_audit()
