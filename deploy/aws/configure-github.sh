#!/usr/bin/env bash
# Configure the GitHub "production" environment for the deploy workflow from
# the outputs of the CloudFormation stack.
#
#   deploy/aws/configure-github.sh [<stack-name>] [<owner/repo>]
#
# Defaults: stack "threatfalcon-server", repo = the current gh repository.
# Needs: aws CLI (credentials for the stack's account), gh CLI (repo admin).
#
# Creates/updates the environment (deployments limited to the main branch)
# and stores the stack outputs as environment secrets, so infrastructure
# identifiers do not appear in the (public) workflow logs.
set -euo pipefail

stack=${1:-threatfalcon-server}
repo=${2:-$(gh repo view --json nameWithOwner --jq .nameWithOwner)}
region=${AWS_REGION:-ap-northeast-1}
env_name=production

output() {
    aws cloudformation describe-stacks --region "$region" --stack-name "$stack" \
        --query "Stacks[0].Outputs[?OutputKey=='$1'].OutputValue" --output text
}

role_arn=$(output DeployRoleArn)
bucket=$(output DeployBucketName)
instance_id=$(output InstanceId)
document=$(output DeployDocumentName)
ingest_url=$(output IngestUrl)
for v in role_arn bucket instance_id document ingest_url; do
    [[ -n ${!v} && ${!v} != None ]] || { echo "stack output for $v is empty; is $stack deployed in $region?" >&2; exit 1; }
done

echo "Configuring environment '$env_name' in $repo"
gh api --method PUT "repos/$repo/environments/$env_name" \
    -F "deployment_branch_policy[protected_branches]=false" \
    -F "deployment_branch_policy[custom_branch_policies]=true" >/dev/null
if ! gh api "repos/$repo/environments/$env_name/deployment-branch-policies" \
    --jq '.branch_policies[] | select(.type == "branch") | .name' | grep -qx main; then
    gh api --method POST "repos/$repo/environments/$env_name/deployment-branch-policies" \
        -f name=main -f type=branch >/dev/null
fi

gh secret set AWS_DEPLOY_ROLE_ARN --repo "$repo" --env "$env_name" --body "$role_arn"
gh secret set DEPLOY_BUCKET --repo "$repo" --env "$env_name" --body "$bucket"
gh secret set DEPLOY_INSTANCE_ID --repo "$repo" --env "$env_name" --body "$instance_id"
gh secret set DEPLOY_SSM_DOCUMENT --repo "$repo" --env "$env_name" --body "$document"
gh variable set PUBLIC_HEALTH_URL --repo "$repo" --env "$env_name" --body "${ingest_url%/api/v1/events}/healthz"
# Repository-level switch read by the deploy job's `if:` (environment
# variables are not available there).
gh variable set SERVER_DEPLOY_ENABLED --repo "$repo" --body true

echo "Done. Deploy with: gh workflow run deploy-server.yml --repo $repo   (or push to main)"
