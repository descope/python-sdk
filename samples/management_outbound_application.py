#!/usr/bin/env python3
"""
Sample script demonstrating outbound application management with Descope Python SDK.

This script shows how to:
1. Create outbound applications (OAuth/OIDC providers)
2. Manage application settings  
3. Handle user tokens for outbound applications

Outbound applications allow Descope to connect to external OAuth/OIDC providers
like Google, Microsoft, Facebook, etc. as a client.
"""

import os
from descope import DescopeClient

def main():
    # Initialize Descope client
    # You'll need to set DESCOPE_PROJECT_ID and DESCOPE_MANAGEMENT_KEY environment variables
    project_id = os.getenv("DESCOPE_PROJECT_ID")
    management_key = os.getenv("DESCOPE_MANAGEMENT_KEY")
    
    if not project_id or not management_key:
        print("Please set DESCOPE_PROJECT_ID and DESCOPE_MANAGEMENT_KEY environment variables")
        return
    
    client = DescopeClient(project_id=project_id, management_key=management_key)
    
    try:
        # 1. Create a new outbound application (Google OAuth)
        print("Creating Google OAuth outbound application...")
        create_resp = client.mgmt.outbound_application.create_application(
            name="My Google Integration",
            client_id="your-google-client-id",
            client_secret="your-google-client-secret",
            template_id="google",  # Use pre-configured Google template
            description="Integration with Google for user authentication",
            default_scopes=["openid", "profile", "email"],
            pkce=True,
            access_type="offline",  # Request refresh tokens
        )
        app_id = create_resp["app"]["id"]
        print(f"✓ Created application with ID: {app_id}")
        
        # 2. Load the created application
        print(f"\nLoading application {app_id}...")
        app_resp = client.mgmt.outbound_application.load_application(app_id)
        print(f"✓ Loaded application: {app_resp['app']['name']}")
        
        # 3. Update the application
        print(f"\nUpdating application {app_id}...")
        client.mgmt.outbound_application.update_application(
            id=app_id,
            name="My Updated Google Integration",
            client_id="your-google-client-id",
            description="Updated description for Google integration",
            default_scopes=["openid", "profile", "email", "https://www.googleapis.com/auth/calendar.readonly"],
        )
        print("✓ Application updated successfully")
        
        # 4. List all outbound applications
        print("\nListing all outbound applications...")
        all_apps_resp = client.mgmt.outbound_application.load_all_applications()
        apps = all_apps_resp["apps"]
        print(f"✓ Found {len(apps)} outbound applications:")
        for app in apps:
            print(f"  - {app['name']} (ID: {app['id']})")
        
        # 5. Token management examples (these would typically be called after users authenticate)
        print(f"\nToken management examples for application {app_id}...")
        
        # Note: These operations would typically be performed after a user has authenticated
        # and you have actual user IDs and tokens to work with
        
        # Example: Fetch user token for outbound application
        # This would retrieve stored OAuth tokens for a user from the external provider
        print("Example: Fetching user token...")
        try:
            token_resp = client.mgmt.outbound_application.fetch_outbound_app_user_token(
                user_id="example-user-id",
                app_id=app_id,
                scopes=["openid", "profile"],
            )
            print("✓ Token fetch would work for authenticated users")
        except Exception as e:
            print(f"ℹ Token fetch example (would work with real user): {str(e)[:100]}...")
        
        # Example: Delete user tokens for an application  
        print("Example: Deleting user tokens...")
        try:
            client.mgmt.outbound_application.delete_outbound_app_user_tokens(
                user_id="example-user-id",
                app_id=app_id,
            )
            print("✓ Token deletion would work for authenticated users")
        except Exception as e:
            print(f"ℹ Token deletion example (would work with real user): {str(e)[:100]}...")
        
        # 6. Clean up - delete the application
        print(f"\nCleaning up - deleting application {app_id}...")
        client.mgmt.outbound_application.delete_application(app_id)
        print("✓ Application deleted successfully")
        
        print("\n🎉 Outbound application management demo completed successfully!")
        
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()