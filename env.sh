docker run --rm -ti  -v "$(realpath .):/app" --privileged -v "/dev/bus/usb:/dev/bus/usb" ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder-lite:latest