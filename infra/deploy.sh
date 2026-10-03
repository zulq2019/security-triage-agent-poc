#!/usr/bin/env bash
# infra/deploy.sh - deploy one environment of the Security Triage & Fix Agent to Azure.
#
# NOT RUN AS PART OF THE POC (no subscription is available). Read docs/infra.md first.
#
# What it does, in order:
#   1. Pre-flight: az login present, right subscription, Bicep compiles and lints (validate.sh), SQL admin set.
#   2. Optional (--create-rg, needs subscription-level rights): what-if + create the resource group (rg.bicep).
#   3. what-if of main.bicep against the resource group - ALWAYS, and shown before anything changes.
#   4. Asks for confirmation (skip with --yes), then az deployment group create.
#   5. Saves the outputs and the generated SQL grant script to infra/out/ and prints the next manual steps.
#
# Usage:
#   export SECAGENT_SQL_ADMIN_OBJECT_ID=<object id of the Entra group that administers Azure SQL>
#   export SECAGENT_SQL_ADMIN_LOGIN=<display name of that group>
#   export SECAGENT_KV_OPERATORS_GROUP_ID=<object id of the group that sets Key Vault secrets>   # optional
#   infra/deploy.sh -p dev -g rg-secagent-dev-uks [-s <subscription id>] [-l uksouth] [--create-rg] [--what-if-only] [--yes]
#
#   -p  parameter file name under infra/params without extension: dev | wipro-hosted | customer-hosted | <your copy>
#   -g  resource group (created only with --create-rg; otherwise it must already exist)
#   -s  subscription id or name (default: the current az account)
#   -l  region for the resource group and the deployment record (default uksouth)
set -euo pipefail
cd "$(dirname "$0")"

PARAMS="" RG="" SUB="" LOCATION="uksouth" CREATE_RG=0 WHATIF_ONLY=0 YES=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    -p) PARAMS="$2"; shift 2 ;;
    -g) RG="$2"; shift 2 ;;
    -s) SUB="$2"; shift 2 ;;
    -l) LOCATION="$2"; shift 2 ;;
    --create-rg) CREATE_RG=1; shift ;;
    --what-if-only) WHATIF_ONLY=1; shift ;;
    --yes) YES=1; shift ;;
    -h|--help) sed -n '2,26p' "$0"; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done
[[ -n "$PARAMS" && -n "$RG" ]] || { echo "Need -p <params> and -g <resource group> (see --help)" >&2; exit 2; }
PARAM_FILE="params/${PARAMS}.bicepparam"
[[ -f "$PARAM_FILE" ]] || { echo "No such parameter file: infra/$PARAM_FILE" >&2; exit 2; }

# --- 1. pre-flight -------------------------------------------------------------------------------------------------
command -v az >/dev/null || { echo "Azure CLI (az) is required" >&2; exit 2; }
az account show >/dev/null 2>&1 || { echo "Run 'az login' first" >&2; exit 2; }
[[ -n "$SUB" ]] && az account set --subscription "$SUB"
echo "Subscription: $(az account show --query '{name:name, id:id, tenant:tenantId}' -o tsv)"

case "${SECAGENT_SQL_ADMIN_OBJECT_ID:-}" in
  ""|00000000-0000-0000-0000-000000000000)
    echo "Set SECAGENT_SQL_ADMIN_OBJECT_ID (and SECAGENT_SQL_ADMIN_LOGIN) to the Entra group that administers Azure SQL." >&2
    exit 2 ;;
esac

./validate.sh

NAME="secagent-${PARAMS}-$(date +%Y%m%d-%H%M%S)"
mkdir -p out

# --- 2. optional resource group (subscription scope) ----------------------------------------------------------------
if [[ $CREATE_RG -eq 1 ]]; then
  RG_TAGS="{\"workload\":\"secagent\",\"parameterFile\":\"${PARAMS}\",\"managedBy\":\"bicep\"}"
  echo "== what-if: resource group $RG ($LOCATION)"
  az deployment sub what-if --name "${NAME}-rg" --location "$LOCATION" --template-file rg.bicep \
    --parameters resourceGroupName="$RG" location="$LOCATION" tags="$RG_TAGS"
  if [[ $WHATIF_ONLY -eq 0 ]]; then
    az deployment sub create --name "${NAME}-rg" --location "$LOCATION" --template-file rg.bicep \
      --parameters resourceGroupName="$RG" location="$LOCATION" tags="$RG_TAGS" -o none
  fi
fi
az group show --name "$RG" >/dev/null 2>&1 || {
  [[ $WHATIF_ONLY -eq 1 && $CREATE_RG -eq 1 ]] && { echo "(what-if only: resource group not created, stopping)"; exit 0; }
  echo "Resource group $RG does not exist (ask the Azure team, or use --create-rg)" >&2; exit 2; }

# --- 3. what-if (always) --------------------------------------------------------------------------------------------
echo "== what-if: main.bicep with $PARAM_FILE into $RG"
az deployment group what-if --name "$NAME" --resource-group "$RG" --parameters "$PARAM_FILE"
[[ $WHATIF_ONLY -eq 1 ]] && { echo "(what-if only: nothing deployed)"; exit 0; }

# --- 4. confirm + deploy --------------------------------------------------------------------------------------------
if [[ $YES -ne 1 ]]; then
  read -r -p "Deploy these changes to $RG? Type the resource group name to confirm: " answer
  [[ "$answer" == "$RG" ]] || { echo "Not confirmed; nothing deployed."; exit 1; }
fi
az deployment group create --name "$NAME" --resource-group "$RG" --parameters "$PARAM_FILE" \
  --query properties.outputs -o json > "out/${NAME}.outputs.json"

# --- 5. outputs and next steps --------------------------------------------------------------------------------------
python3 - "out/${NAME}.outputs.json" "out/${NAME}.sql-grants.sql" <<'PY'
import json, sys
o = json.load(open(sys.argv[1]))
open(sys.argv[2], "w").write(o["sqlGrantScript"]["value"])
PY
SQL_FQDN=$(python3 -c "import json;print(json.load(open('out/${NAME}.outputs.json'))['sqlServerFqdn']['value'])")
SQL_DB=$(python3 -c "import json;print(json.load(open('out/${NAME}.outputs.json'))['sqlDatabase']['value'])")
KV_URI=$(python3 -c "import json;print(json.load(open('out/${NAME}.outputs.json'))['keyVaultUri']['value'])")
INTAKE=$(python3 -c "import json;print(json.load(open('out/${NAME}.outputs.json'))['intakeUrl']['value'])")

cat <<NEXT

Deployed. Outputs: infra/out/${NAME}.outputs.json

Next steps (manual, see docs/infra.md "After the first deployment"):
  1. Database schema and app users - as a member of the SQL admin group, from a network that can reach the server:
       sqlcmd -S ${SQL_FQDN} -d ${SQL_DB} -G -i ../db/schema.sql
       sqlcmd -S ${SQL_FQDN} -d ${SQL_DB} -G -i ../db/migrations/002_model_usage.sql
       sqlcmd -S ${SQL_FQDN} -d ${SQL_DB} -G -i out/${NAME}.sql-grants.sql
  2. Secrets - set values in ${KV_URI} (never in git), e.g.:
       az keyvault secret set --vault-name <vault> --name secagent-hmac-key --value "\$(openssl rand -base64 48)"
     then reference them per app with the appKeyVaultReferences parameter and redeploy.
  3. Images - push secagent-<app> images to the registry, set usePlaceholderImages = false (or imageOverrides
     with digests) and run this script again.
  4. Webhook - point the GitHub / SARIF webhook at ${INTAKE} (signature secret in Key Vault).
NEXT
