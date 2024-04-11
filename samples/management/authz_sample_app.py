import json
import logging

from descope import AuthException, DescopeClient

logging.basicConfig(level=logging.INFO)


def main():
    # Either specify here or read from env
    project_id = ""
    management_key = ""

    try:
        descope_client = DescopeClient(
            project_id=project_id, management_key=management_key
        )
        try:
            logging.info("Creating test authz schema if different name")
            schema = descope_client.mgmt.authz.load_schema()
            with open("samples/management/files.json") as f:
                schema_from_file = json.load(f)
                if schema["name"] != schema_from_file["name"]:
                    logging.info("Schema is different, upgrading...")
                    descope_client.mgmt.authz.save_schema(schema_from_file, True)
                    descope_client.mgmt.authz.create_relations(
                        [
                            {
                                "resource": "Dev",
                                "relationDefinition": "parent",
                                "namespace": "org",
                                "target": "Descope",
                            },
                            {
                                "resource": "Sales",
                                "relationDefinition": "parent",
                                "namespace": "org",
                                "target": "Descope",
                            },
                            {
                                "resource": "Dev",
                                "relationDefinition": "member",
                                "namespace": "org",
                                "target": "u1",
                            },
                            {
                                "resource": "Dev",
                                "relationDefinition": "member",
                                "namespace": "org",
                                "target": "u3",
                            },
                            {
                                "resource": "Sales",
                                "relationDefinition": "member",
                                "namespace": "org",
                                "target": "u2",
                            },
                            {
                                "resource": "Presentations",
                                "relationDefinition": "parent",
                                "namespace": "folder",
                                "target": "Internal",
                            },
                            {
                                "resource": "roadmap.ppt",
                                "relationDefinition": "parent",
                                "namespace": "doc",
                                "target": "Presentations",
                            },
                            {
                                "resource": "roadmap.ppt",
                                "relationDefinition": "owner",
                                "namespace": "doc",
                                "target": "u1",
                            },
                            {
                                "resource": "Internal",
                                "relationDefinition": "viewer",
                                "namespace": "folder",
                                "targetSetResource": "Descope",
                                "targetSetRelationDefinition": "member",
                                "targetSetRelationDefinitionNamespace": "org",
                            },
                            {
                                "resource": "Presentations",
                                "relationDefinition": "editor",
                                "namespace": "folder",
                                "targetSetResource": "Sales",
                                "targetSetRelationDefinition": "member",
                                "targetSetRelationDefinitionNamespace": "org",
                            },
                        ]
                    )
            res = descope_client.mgmt.authz.has_relations(
                [
                    {
                        "resource": "roadmap.ppt",
                        "relationDefinition": "owner",
                        "namespace": "doc",
                        "target": "u1",
                    },
                    {
                        "resource": "roadmap.ppt",
                        "relationDefinition": "editor",
                        "namespace": "doc",
                        "target": "u1",
                    },
                    {
                        "resource": "roadmap.ppt",
                        "relationDefinition": "viewer",
                        "namespace": "doc",
                        "target": "u1",
                    },
                    {
                        "resource": "roadmap.ppt",
                        "relationDefinition": "viewer",
                        "namespace": "doc",
                        "target": "u3",
                    },
                    {
                        "resource": "roadmap.ppt",
                        "relationDefinition": "editor",
                        "namespace": "doc",
                        "target": "u3",
                    },
                    {
                        "resource": "roadmap.ppt",
                        "relationDefinition": "editor",
                        "namespace": "doc",
                        "target": "u2",
                    },
                ]
            )
            logging.info(f"Checking existing relations: {res}")
        except AuthException as e:
            logging.info(f"Checking existing relations failed {e}")

    except AuthException:
        raise


if __name__ == "__main__":
    main()
