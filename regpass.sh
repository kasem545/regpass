#!/bin/bash

prompt() {
    local var_name=$1
    local prompt_text=$2
    local default=$3

    read -p "$prompt_text [$default]: " input
    eval "$var_name=\"\${input:-$default}\""
}

prompt MIN_LENGTH "Minimum password length" 8
prompt MAX_LENGTH "Maximum password length" 64
prompt REQUIRE_UPPERCASE "Require uppercase letters? (yes/no)" yes
prompt REQUIRE_LOWERCASE "Require lowercase letters? (yes/no)" yes
prompt REQUIRE_DIGIT "Require digits? (yes/no)" yes
prompt REQUIRE_SPECIAL "Require special characters? (yes/no)" yes

# Enable tab-completion for file path
read -e -i "" -p "Path to wordlist file []: " WORDLIST
WORDLIST="${WORDLIST:-}"

FILTER_CMD="cat \"$WORDLIST\""
FILTER_CMD+=" | grep -E '^.{$MIN_LENGTH,$MAX_LENGTH}$'"

[[ "$REQUIRE_UPPERCASE" == "yes" ]] && FILTER_CMD+=" | grep -E '[A-Z]'"
[[ "$REQUIRE_LOWERCASE" == "yes" ]] && FILTER_CMD+=" | grep -E '[a-z]'"
[[ "$REQUIRE_DIGIT" == "yes" ]]     && FILTER_CMD+=" | grep -E '[0-9]'"
[[ "$REQUIRE_SPECIAL" == "yes" ]]   && FILTER_CMD+=" | grep -E '[^a-zA-Z0-9]'"

echo -e "\nMatching passwords from '$WORDLIST':"
eval "$FILTER_CMD"
echo -e "\nPassword generation complete."