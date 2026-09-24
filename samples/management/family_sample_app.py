"""
End-to-end walkthrough of the family account management API.

Creates throwaway attribute definitions, a family, a guardian and a dependent, exercises every
family endpoint, then deletes everything it created and restores the original family settings.

Run:
    DESCOPE_PROJECT_ID=... DESCOPE_MANAGEMENT_KEY=... uv run python samples/management/family_sample_app.py

Optional environment variables:
    DESCOPE_BASE_URL - override the Descope API base URL (e.g. for a custom domain).
    SKIP_CLEANUP=1   - keep everything the run created (and the guardian's membership) for inspection.
    FAMILY_ROLE      - the guardian's role in the family. Defaults to "Family Admin", the default family
                       role Descope creates when family accounts are enabled. A different role needs the
                       "Family Impersonate Dependents" permission for the impersonation step to pass.

The script exits with a non-zero status if any step, including a cleanup step, fails.
"""

import json
import logging
import os
import sys
import time
from typing import Any, Callable, List, Optional

from descope import AssociatedFamily, CustomAttribute, DescopeClient

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)

# Custom attribute type 1 is a string attribute
STRING_ATTRIBUTE = 1


def step(name: str, call: Callable[[], Any], log_result: bool = True) -> Any:
    """Run a single step, logging its result. Exceptions propagate to the caller."""
    result = call()
    logger.info(f"\n[ok] {name}")
    if log_result and result is not None:
        logger.info(json.dumps(result, indent=2, default=str))
    return result


def main() -> int:
    project_id = os.getenv("DESCOPE_PROJECT_ID")
    management_key = os.getenv("DESCOPE_MANAGEMENT_KEY")
    base_url = os.getenv("DESCOPE_BASE_URL") or None
    guardian_role = os.getenv("FAMILY_ROLE") or "Family Admin"
    skip_cleanup = os.getenv("SKIP_CLEANUP") == "1"

    if not project_id or not management_key:
        logger.error("Missing DESCOPE_PROJECT_ID or DESCOPE_MANAGEMENT_KEY environment variables")
        return 1

    descope_client = DescopeClient(project_id=project_id, management_key=management_key, base_url=base_url)
    family = descope_client.mgmt.family
    user = descope_client.mgmt.user

    # Unique suffix so reruns and parallel runs don't collide
    run = format(int(time.time() * 1000), "x")
    family_attr = f"plan_{run}"
    family_scoped_attr = f"nickname_{run}"
    guardian_login_id = f"guardian-{run}@example.com"

    # --- Settings -----------------------------------------------------------------------------
    original_settings = step("family.load_settings", family.load_settings)
    step(
        "family.update_settings (enable families)",
        lambda: family.update_settings(enabled=True, allow_multiple_families_users=True),
    )

    family_id: Optional[str] = None
    dependent_user_id: Optional[str] = None
    guardian_created = False
    family_attr_created = False
    family_scoped_attr_created = False
    failed = False

    try:
        # --- Attribute definitions ------------------------------------------------------------
        # Family attributes live on the family entity; family-scoped attributes are user attributes
        # whose values are stored per family membership.
        step(
            "family.create_custom_attributes",
            lambda: family.create_custom_attributes(
                [CustomAttribute(family_attr, STRING_ATTRIBUTE, display_name="Plan")]
            ),
        )
        family_attr_created = True
        step("family.load_custom_attributes", family.load_custom_attributes)

        step(
            "user.create_family_scoped_custom_attributes",
            lambda: user.create_family_scoped_custom_attributes(
                [CustomAttribute(family_scoped_attr, STRING_ATTRIBUTE, display_name="Nickname")]
            ),
        )
        family_scoped_attr_created = True
        step("user.load_family_scoped_custom_attributes", user.load_family_scoped_custom_attributes)

        # --- Family CRUD ----------------------------------------------------------------------
        created = step(
            "family.create",
            lambda: family.create(f"Demo Family {run}", custom_attributes={family_attr: "free"}),
        )
        family_id = created["family"]["id"]
        fid: str = family_id

        step(
            "family.update (rename + change attribute)",
            lambda: family.update(fid, name=f"Demo Family {run} (renamed)", custom_attributes={family_attr: "premium"}),
        )
        step("family.search by id", lambda: family.search(family_ids=[fid]))
        step(
            "family.search by custom attribute",
            lambda: family.search(custom_attributes={family_attr: "premium"}),
        )

        # --- Guardian (regular member) --------------------------------------------------------
        # A user can be created straight into a family, or added later with user.add_families.
        step(
            "user.create (guardian, created into the family)",
            lambda: user.create(
                guardian_login_id,
                email=guardian_login_id,
                display_name="Demo Guardian",
                family_associations=[
                    AssociatedFamily(
                        fid, role_names=[guardian_role], family_scoped_attributes={family_scoped_attr: "Mom"}
                    )
                ],
            ),
        )
        guardian_created = True

        # add_families on a family the user already belongs to merges - here it updates the nickname only
        guardian = step(
            "user.add_families (update family-scoped attribute)",
            lambda: user.add_families(
                guardian_login_id,
                [AssociatedFamily(fid, family_scoped_attributes={family_scoped_attr: "Mommy"})],
            ),
        )
        logger.info(f"  guardian userFamilies -> {guardian['user'].get('userFamilies')}")

        # --- Dependent (no login credentials of their own) ------------------------------------
        dependent = step(
            "family.create_dependent",
            lambda: family.create_dependent(
                fid,
                name=f"Demo Kid {run}",
                given_name="Demo",
                family_scoped_attributes={fid: {family_scoped_attr: "Kiddo"}},
            ),
        )["user"]
        dependent_user_id = dependent["userId"]
        logger.info(f"  dependent.dependent -> {dependent.get('dependent')}")

        # --- Search users by family -----------------------------------------------------------
        members = step("user.search_all (all family members)", lambda: user.search_all(family_ids=[fid]))
        logger.info(f"  member login IDs -> {[u.get('loginIds') for u in members['users']]}")
        step(
            "user.search_all (dependents only)",
            lambda: user.search_all(family_ids=[fid], dependent=True),
        )

        # --- Impersonation --------------------------------------------------------------------
        # The guardian acts as family admin through guardian_role's impersonate-dependents permission
        impersonation_jwt = step(
            "family.impersonate_dependent",
            lambda: family.impersonate_dependent(guardian_login_id, dependent["loginIds"][0], fid),
            log_result=False,  # keep session tokens out of the logs
        )
        step("family.stop_impersonation", lambda: family.stop_impersonation(impersonation_jwt), log_result=False)

        # --- Membership removal ---------------------------------------------------------------
        # Kept when skipping cleanup, so the family shows both the guardian and the dependent
        if not skip_cleanup:
            step(
                "user.remove_families (guardian)",
                lambda: user.remove_families(guardian_login_id, [fid]),
            )
    except Exception as e:
        failed = True
        logger.error(f"\n[failed] {e}")
    finally:
        if skip_cleanup:
            logger.info("\n--- SKIP_CLEANUP=1, left in place ---")
            logger.info(
                json.dumps(
                    {
                        "familyId": family_id,
                        "familyAttribute": family_attr if family_attr_created else None,
                        "familyScopedUserAttribute": family_scoped_attr if family_scoped_attr_created else None,
                        "guardianLoginId": guardian_login_id if guardian_created else None,
                        "dependentUserId": dependent_user_id,
                        "originalSettings": original_settings,
                    },
                    indent=2,
                )
            )
        else:
            # --- Cleanup, reverse order -------------------------------------------------------
            # Every cleanup step is attempted even if an earlier one fails, and any failure makes
            # the script exit non-zero.
            logger.info("\n--- cleanup ---")
            cleanup: List[tuple] = []
            if dependent_user_id:
                dep_id: str = dependent_user_id
                cleanup.append(("family.delete_dependent", lambda: family.delete_dependent(dep_id)))
            if guardian_created:
                cleanup.append(("user.delete (guardian)", lambda: user.delete(guardian_login_id)))
            if family_id:
                del_id: str = family_id
                cleanup.append(("family.delete", lambda: family.delete(del_id)))
            if family_scoped_attr_created:
                cleanup.append(
                    (
                        "user.delete_family_scoped_custom_attributes",
                        lambda: user.delete_family_scoped_custom_attributes([family_scoped_attr]),
                    )
                )
            if family_attr_created:
                cleanup.append(
                    ("family.delete_custom_attributes", lambda: family.delete_custom_attributes([family_attr]))
                )
            max_members = original_settings.get("maxFamilyMembers")
            cleanup.append(
                (
                    "family.update_settings (restore original)",
                    lambda: family.update_settings(
                        enabled=original_settings.get("enabled", False),
                        max_family_members=max_members if max_members else None,
                        allow_multiple_families_users=original_settings.get("allowMultipleFamiliesUsers", False),
                    ),
                )
            )
            for name, call in cleanup:
                try:
                    step(name, call)
                except Exception as e:
                    failed = True
                    logger.error(f"\n[failed] {name}: {e}")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
