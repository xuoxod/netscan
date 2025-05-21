#!/bin/bash

banner="Welcome to Splash!"
for ((i=0; i<=${#banner}; i++)); do
    printf "\r%s" "${banner:0:i}"
    sleep 0.1
done
echo

#!/bin/bash

messages=("Loading" "Checking dependencies" "Almost there" "Ready!")
spinner="/-\|"
for i in {0..39}; do
    msg="${messages[$((i/10))]}"
    spin="${spinner:i%4:1}"
    printf "\r%s... %c" "$msg" "$spin"
    sleep 0.1
done
echo

#!/bin/bash

for i in {5..1}; do
    printf "\rStarting in %d..." "$i"
    sleep 1
done
echo -e "\rLet's go!      "


#!/bin/bash

frames=(
"  (•_•) "
" ( •_•)>⌐■-■ "
" (⌐■_■) "
)
for i in {0..2}; do
    printf "\r%s" "${frames[$i]}"
    sleep 0.5
done
echo