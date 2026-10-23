package transformguard

import "testing"

func TestCredentialGuardRuntimeMetadata(t *testing.T) {
	runtime := []string{"AWS_EXECUTION_ENV=AWS_ECS_FARGATE", "AWS_REGION=us-east-2", "AWS_DEFAULT_REGION=us-east-2"}
	if !credentialFree(nil) || !credentialFree(runtime) {
		t.Fatal("documented ECS runtime metadata rejected as credentials")
	}
	for _, entry := range []string{
		"AWS_EXECUTION_ENV=AWS_ECS_EC2", "AWS_REGION=us-west-2", "AWS_DEFAULT_REGION=us-west-2",
		"AWS_ACCESS_KEY_ID=synthetic", "AWS_SECRET_ACCESS_KEY=synthetic", "AWS_SESSION_TOKEN=synthetic",
		"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI=/synthetic", "AWS_CONTAINER_CREDENTIALS_FULL_URI=http://127.0.0.1",
		"AWS_CONTAINER_AUTHORIZATION_TOKEN=synthetic", "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE=/synthetic",
		"AWS_WEB_IDENTITY_TOKEN_FILE=/synthetic", "AWS_ROLE_ARN=synthetic", "AWS_PROFILE=synthetic",
		"AWS_SHARED_CREDENTIALS_FILE=/synthetic", "AWS_CONFIG_FILE=/synthetic",
		"AWS_ENDPOINT_URL=http://127.0.0.1", "AWS_FUTURE_CREDENTIAL_SOURCE=synthetic",
		"CSV_TLS_BOOTSTRAP=synthetic",
	} {
		t.Run(entry, func(t *testing.T) {
			env := append(append([]string(nil), runtime...), entry)
			if credentialFree(env) {
				t.Fatal("unexpected credential/configuration source accepted")
			}
		})
	}
	t.Setenv("CSV_TLS_BOOTSTRAP", "synthetic")
	if NoCredentials() {
		t.Fatal("public check did not inspect process environment")
	}
}
