# Decisions and assumptions (vitrag track)

## Process
1. V0 was skipped on the human's instruction. The Wazuh private keys committed in `7d5be0a` under
   `vitrag/wazuh-certificates/` are untouched; they are in git history and must be treated as exposed.
2. Branch `feat/vitrag-lab` was created from `origin/main` (7d5be0a) after `git pull`.
3. The build sandbox has no Docker daemon, so compose, Dockerfiles, nginx config, `docker network disconnect`
   and Wazuh are written but not run. See PLAN.md for what is tested instead.
4. Work order was changed by the human: V3 (attack scenarios) is done last, after a check-in.
