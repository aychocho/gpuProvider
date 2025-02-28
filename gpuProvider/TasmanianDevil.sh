#!/bin/bash
# Shellc to convert this to a binary
# Static build of osslsigncode packaged with this binary
# Static build of busybox for POSIX shell tampering protection
# Static build of stress for stressing the gpu or implement in bash
# Static build of perl or refactor to bash/c for the extract-module-script
set -eu
# String list of the GPUs the system is supposed to have
EXPECTED_GPUS=""

# JSON vars
PCI_DEVICE_ID=""
PCI_VENDOR_ID=""
SUBSYSTEM_VENDOR_ID=""
SUBSYSTEM_DEVICE_ID=""
GPU_UUID=""
VBIOS_VERSION=""
GPU_NAME=""
VBIOS_INTEGRITY=""
KERNEL_MODULE_CHECK="fail"
SECURE_BOOT=""
KERNEL_IMAGE_CHECK=""
VM_CHECK=""


function secure_boot_check() {
    # 2 methods, kernel log & EFI vars
    # same on all distros
    secure_boot_var_file="/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
    if [ ! -f "$secure_boot_var_file" ]; then
        SECURE_BOOT="N"
    fi
    secureboot_efivar=$(od --address-radix=n --format=u1 $secure_boot_var_file 2>/dev/null | cut -c20-)
    if [[ $secureboot_efivar -ne 1 ]]; then
       #echo "Test Failed Secure Boot not enabled"
       SECURE_BOOT="N"
    fi
    
    # if ! journalctl -xb | grep "Secure Boot"; then
       # echo "Test Failed: System not booted with secure-boot capable kernel"
       # SECURE_BOOT="N"
       # return 1
    # fi
    #echo "Secure boot check passed"
    SECURE_BOOT="Y"
}
# modinfo isn't used here because busybox modinfo doesn't support signature signing :(
     
 function kernel_mod_sig_check() {
    for module in $(lsmod | awk 'NR>1 {print $1}'); do
        # Skip aliased modules & Nvidia modules
        if grep -E " $module$" /lib/modules/$(uname -r)/modules.alias > /dev/null; then
            continue
        fi
        if grep -E " $module" /lib/modules/$(uname -r)/modules.symbols > /dev/null; then
            continue
        fi
        # NVIDIA cards won't load the driver unless it's signed so if it's loaded
        # the sig is valid. I can't seem to find their public key because the one
        # they give in the driver is corrupt (seems to be a known issue)
        # generics are weird abstractions for modules that aren't really modules
        # they exist but don't have a signature, they are essentially just a function call
        # to another module
        # nls is language mods that again don't exist :( so many special cases
        if echo $module | grep -E 'nvidia|generic|nls|dmi' > /dev/null; then
            continue
        fi

        # Find module file (handle both .ko and .ko.zst)
        file_path=$(find /lib/modules/$(uname -r)/ -type f \( -name "$module.ko" -o -name "$module.ko.zst" \) -print -quit)

        if [[ -z "$file_path" ]]; then
            echo "Error: Module $module not found"
            return 1
        fi

        # Check if module is from dpkg
        if ! dpkg -S "$file_path" >/dev/null 2>&1; then
            echo "Warning: Module $module is  not registered in dpkg"
            return 1
        fi

        # Handle zst compressed modules
        if [[ "$file_path" == *.zst ]]; then
            tmp_file="/tmp/$module.ko"
            zstd -d --stdout "$file_path" > "$tmp_file"
        else
            tmp_file="$file_path"
        fi

        # might want to refactor this script later
        # set -eu it will error and return 1 if this fails automagically
        perl /home/wallaby/extract-kernel-sig.pl /tmp/kernel-mod.pem $tmp_file &> /dev/null

        # Cleanup decompressed file if necessary
        [[ "$file_path" == *.zst ]] && rm -f "$tmp_file"
    done
    # if all went through without errors
    KERNEL_MODULE_CHECK="pass"
}

function kernel_image_sig_check() {
    if ! osslsigncode verify -in /boot/vmlinuz-$(uname -r) -CAfile /tmp/ubuntu-uefi.pem &> /dev/null; then
        echo "Kernel image failed signature check"
        KERNEL_IMAGE_CHECK="fail"
        return 1
    fi
    #echo "Kernel Image Check Passed"
    KERNEL_IMAGE_CHECK="pass"

}
function vbios_check() {
    # Linux is weird, this type of thing depends on the init systems configuration on 
    # how to treat system file permissions, su -c is a surefire way.
    PCI_BUS_PATHS="$(lspci | grep VGA | grep NVIDIA | awk '{print $1}')"
    for id in $PCI_BUS_PATHS; do
        # prime rom for reading
        romfile="/tmp/rom.rom"
        su -c "echo 1 > /sys/bus/pci/devices/0000:$id/rom"
        su -c "cat /sys/bus/pci/devices/0000:$id/rom > $romfile"
        su -c "echo 0 > /sys/bus/pci/devices/0000:$id/rom"
     
        if [[ ! -f "$romfile" ]]; then
            echo "ROM File not found"
            return 1
        fi
        # Rom sig checking refactored from https://github.com/awilliam/rom-parser/blob/master/rom-parser.c 
        # Check for ROM signature (0x55AA at the beginning)
        local sig=$(xxd -p -l 2 "$romfile")
        if [[ "$sig" != "55aa" ]]; then
            echo "Invalid ROM: Missing 0x55AA signature"
            VBIOS_INTEGRITY="fail"
            return 1
        fi
    
        # # Search for PCIR signature (I don't think nvidia does this)
        # if ! grep -q "PCIR" <(xxd -p "$romfile"); then
            # echo "Invalid ROM: Missing PCIR signature"
            # return 1
        # fi
    
        #echo "Valid ROM signature found for $id"
    done
    VBIOS_INTEGRITY="pass"
    return 0
}
function pciid_check() { 
    # This is how most software detects what GPU is in use
    # Get all nvidia gpu's (10de vendor id)
    local VGA_IDS=$(lspci -ns  $(lspci | grep VGA | awk '{print $1}') | awk '{print $3}' | grep "10de")
    local SUBSYSTEM_IDS=$(lspci -vns  $(lspci | grep VGA | awk '{print $1}') | grep -Eo 'Subsystem:.*' | sed 's/Subsystem:\ //g')
    # get what gpu we expect from the ids
    for id in "$VGA_IDS"; do
        PCI_VENDOR_ID+=$(sed 's/:.*//g' <<< $id)
        PCI_DEVICE_ID+=$(sed 's/.*://g' <<< $id)
        SUBSYSTEM_VENDOR_ID+=$(sed 's/:.*//g' <<< $SUBSYSTEM_IDS)
        SUBSYSTEM_DEVICE_ID+=$(sed 's/.*://g' <<< $SUBSYSTEM_IDS)
    done
}

function vm_check() {
    # Check for hypervisor output in kernel log
    if dmesg | grep -q "hypervisor" || dmesg | grep -q "KVM" || dmesg | grep -q "Xen" || dmesg | grep -q "VMware"; then
      echo "Hypervisor signatures found in kernel log."
      VM_CHECK="fail"
      return 1
    fi

    # Check for VFIO kernel module
    if lsmod | grep -q "vfio"; then
      echo "VFIO kernel module loaded."
      VM_CHECK="fail"
      return 1
    fi

    # CPU Frequency Check
    # VMs (especially qemu) cannot emulate CPU frequency scaling (i.e Turbo Boost)
    # since it has been a feature on all processors post 2005, we can check for 
    # it to see if the user is using a VM.
    if [[ ! -f /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq ]]; then
      echo "VM Check Failed: CPU does not support scaling"
      VM_CHECK="fail"
      return 1
    fi
    # too temperemental
    # cpu_freq_start=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq)
    # # need to build a statically linked copy of this or find some other way to stress the system
    # stress -c $(nproc) > /dev/null &
    # sleep 10

    # cpu_freq_end=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq)

    # killall stress &> /dev/null

    # if [[ -z "$cpu_freq_start" || -z "$cpu_freq_end" ]]; then
        # echo "Could not read CPU frequency."
        # return 1 # Treat as potential VM as we cannot check
    # fi


    # freq_diff=$(( ($cpu_freq_end - $cpu_freq_start) * 100 / $cpu_freq_start ))

    # if (( $(echo "$freq_diff > 0.1 || $freq_diff < -0.1" | bc -l) )); then
        #echo "VM Check Passed"
    VM_CHECK="pass"
    #    return 0  # Not a VM frequency changed significantly
    # else
        # echo "CPU frequency change within acceptable range ($freq_diff%). This suggests a potential VM."
        # VM_CHECK="fail"
        # return 1  # Is a vm
    # fi
}
function get_info() {
    INFO="$(cat /proc/driver/nvidia/gpus/0000:$(lspci | grep VGA | awk '{print $1}')/information)"
    GPU_NAME=$(grep -Eo 'NVIDIA.*' <<< "$INFO")
    GPU_UUID=$(grep -Eo 'GPU-.*' <<< "$INFO")
    VBIOS_VERSION=$(grep -i "Video Bios" <<< "$INFO" | awk -F: '{print $2}' | xargs)
}

# Temp files
# from https://wiki.debian.org/SecureBoot
# cat >> /tmp/debian-uefi.pem << EOF
# -----BEGIN CERTIFICATE-----
# MIIDnjCCAoagAwIBAgIRAO1UodWvh0iUjZ+JMu6cfDQwDQYJKoZIhvcNAQELBQAw
# IDEeMBwGA1UEAxMVRGViaWFuIFNlY3VyZSBCb290IENBMB4XDTE2MDgxNjE4MDkx
# OFoXDTQ2MDgwOTE4MDkxOFowIDEeMBwGA1UEAxMVRGViaWFuIFNlY3VyZSBCb290
# IENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnZXUi5vaEKwuyoI3
# waTLSsMbQpPCeinTbt1kr4Cv6maiG2GcgwzFa7k1Jf/F++gpQ97OSz3GEk2x7yZD
# lWjNBBH+wiSb3hTYhlHoOEO9sZoV5Qhr+FRQi7NLX/wU5DVQfAux4gOEqDZI5IDo
# 6p/6v8UYe17OHL4sgHhJNRXAIc/vZtWKlggrZi9IF7Hn7IKPB+bK4F9xJDlQCo7R
# cihQpZ0h9ONhugkDZsjfTiY2CxUPYx8rr6vEKKJWZIWNplVBrjyIld3Qbdkp29jE
# aLX89FeJaxTb4O/uQA1iH+pY1KPYugOmly7FaxOkkXemta0jp+sKSRRGfHbpnjK0
# ia9XeQIDAQABo4HSMIHPMEEGCCsGAQUFBwEBBDUwMzAxBggrBgEFBQcwAoYlaHR0
# cHM6Ly9kc2EuZGViaWFuLm9yZy9zZWN1cmUtYm9vdC1jYTAfBgNVHSMEGDAWgBRs
# zs5+TGwNH2FJ890n38xcu0GeoTAUBglghkgBhvhCAQEBAf8EBAMCAPcwEwYDVR0l
# BAwwCgYIKwYBBQUHAwMwDgYDVR0PAQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8w
# HQYDVR0OBBYEFGzOzn5MbA0fYUnz3SffzFy7QZ6hMA0GCSqGSIb3DQEBCwUAA4IB
# AQB3lj5Hyc4Jz4uJzlntJg4mC7mtqSu9oeuIeQL/Md7+9WoH72ETEXAev5xOZmzh
# YhKXAVdlR91Kxvf03qjxE2LMg1esPKaRFa9VJnJpLhTN3U2z0WAkLTJPGWwRXvKj
# 8qFfYg8wrq3xSGZkfTZEDQY0PS6vjp3DrcKR2Dfg7npfgjtnjgCKxKTfNRbCcitM
# UdeTk566CA1Zl/LiKaBETeru+D4CYMoVz06aJZGEP7dax+68a4Cj2f2ybXoeYxTr
# 7/GwQCXV6A6B62v3y//lIQAiLC6aNWASS1tfOEaEDAacz3KTYhjuXJjWs30GJTmV
# 305gdrAGewiwbuNknyFWrTkP
# -----END CERTIFICATE-----
# EOF
cat > /tmp/ubuntu-uefi.pem << EOF
-----BEGIN CERTIFICATE-----
MIIENDCCAxygAwIBAgIJALlBJKAYLJJnMA0GCSqGSIb3DQEBCwUAMIGEMQswCQYD
VQQGEwJHQjEUMBIGA1UECAwLSXNsZSBvZiBNYW4xEDAOBgNVBAcMB0RvdWdsYXMx
FzAVBgNVBAoMDkNhbm9uaWNhbCBMdGQuMTQwMgYDVQQDDCtDYW5vbmljYWwgTHRk
LiBNYXN0ZXIgQ2VydGlmaWNhdGUgQXV0aG9yaXR5MB4XDTEyMDQxMjExMTI1MVoX
DTQyMDQxMTExMTI1MVowgYQxCzAJBgNVBAYTAkdCMRQwEgYDVQQIDAtJc2xlIG9m
IE1hbjEQMA4GA1UEBwwHRG91Z2xhczEXMBUGA1UECgwOQ2Fub25pY2FsIEx0ZC4x
NDAyBgNVBAMMK0Nhbm9uaWNhbCBMdGQuIE1hc3RlciBDZXJ0aWZpY2F0ZSBBdXRo
b3JpdHkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC/WzoWdO4hXa5h
7Z1WrL3e3nLz3X4tTGIPrMBtSAgRz42L+2EfJ8wRbtlVPTlU60A7sbvihTR5yvd7
v7p6yBAtGX2tWc+m1OlOD9quUupMnpDOxpkNTmdleF350dU4Skp6j5OcfxqjhdvO
+ov3wqIhLZtUQTUQVxONbLwpBlBKfuqZqWinO8cHGzKeoBmHDnm7aJktfpNS5fbr
yZv5K+24aEm82ZVQQFvFsnGq61xX3nH5QArdW6wehC1QGlLW4fNrbpBkT1u06yDk
YRDaWvDq5ELXAcT+IR/ZucBUlUKBUnIfSWR6yGwk8QhwC02loDLRoBxXqE3jr6WO
BQU+EEOhAgMBAAGjgaYwgaMwHQYDVR0OBBYEFK2RmQvCKrH1FwSMI7ZlWiaONFpj
MB8GA1UdIwQYMBaAFK2RmQvCKrH1FwSMI7ZlWiaONFpjMA8GA1UdEwEB/wQFMAMB
Af8wCwYDVR0PBAQDAgGGMEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6Ly93d3cuY2Fu
b25pY2FsLmNvbS9zZWN1cmUtYm9vdC1tYXN0ZXItY2EuY3JsMA0GCSqGSIb3DQEB
CwUAA4IBAQA/ffZ2pbODtCt60G1SGgODxBKnUJxHkszAlHeC0q5Xs5kE9TI6xlUd
B9sSqVb62NR2IOvkw1Hbmlyckj8Yc9qUaqGZOIykiG3B/Dlx0HR2FgM+ViM11VVH
WxodQcLTEkzc/64KkpxiChcBnHPgXrH9vNa1GRF6fs0+A35m21uoyTlIUf9T4Zwx
U5EbOxB1Axe65oECgJRwTEa3lLA9Fc0fjgLgaAKP+/lHHX2iAcYHUcSazO3dz6Nd
7ZK7vtH95uwfM1FzBL48crB9CPgB/5h9y5zgaTl3JUdxiLGNJ6UuqPc/X4Bplz6p
9JkU284DDgtmxBxtvbgnd8FClL38agq8
-----END CERTIFICATE-----
EOF
cat > /tmp/kernel-mod.pem << EOF
-----BEGIN CERTIFICATE-----
MIIDrTCCApWgAwIBAgIUGE62Tngc/xJVVpwkjXsMeNj3jGQwDQYJKoZIhvcNAQEL
BQAwPjE8MDoGA1UEAwwzd2FsbGFieS1BbGwtU2VyaWVzIFNlY3VyZSBCb290IE1v
ZHVsZSBTaWduYXR1cmUga2V5MCAXDTI1MDIxMjEyNDUxNVoYDzIxMjUwMTE5MTI0
NTE1WjA+MTwwOgYDVQQDDDN3YWxsYWJ5LUFsbC1TZXJpZXMgU2VjdXJlIEJvb3Qg
TW9kdWxlIFNpZ25hdHVyZSBrZXkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQCIAVS0uX/ppLgpDiX+7cjQc6NjFXYBaoF9qpejuAP/3YYF+NTfuAMxV5Fk
kk+PyV2Go94IR3ev/KsSvIqR8tVtlT+FZHw8Gu0ocobAwHnx6tiHz0aMaMPmYSmH
xdcVhW5OWBZwGickREba9neW0TSDZRswDI0QUxrbYA1IF06i4ec1ayPyDlzmvRjW
zGPGRL7zDrzBRv7dhI3qwAD4SqxBk3W2VvtJuWJ2BQiUr5gjI+kULzI7NJ4Yj7QY
UOZoGuECx5VUtugr7Bsx/vu6WuKyzVYh99nNRjCtaAfKk1MCgC1xLNYsFTt0Jiwm
MBynUeytelSYE4FMz9LxFsgVDmHBAgMBAAGjgaAwgZ0wHQYDVR0OBBYEFD4JEsX6
19FAHqmcVyBCGf/1/TfDMB8GA1UdIwQYMBaAFD4JEsX619FAHqmcVyBCGf/1/TfD
MAwGA1UdEwEB/wQCMAAwHwYDVR0lBBgwFgYIKwYBBQUHAwMGCisGAQQBkggQAQIw
LAYJYIZIAYb4QgENBB8WHU9wZW5TU0wgR2VuZXJhdGVkIENlcnRpZmljYXRlMA0G
CSqGSIb3DQEBCwUAA4IBAQB9+YqzD5qtgiDBZ8erb1yFkhJb6O8gTes0i0Pghs8n
GMocFQcNrhp70NgUwttG3qJ4znT9xZIuhuKGErOx1LUhvLTdn6gskVcVrvLRdqqZ
2qb1lGNfm+0yyxoX4lY/tUSblh5eNbAwK++evdiJElJT/6bjNCAuHnBUmavHlvv4
C6x+xAilVETm7utsAtcpKHxCuqTJBBsgxufddScL9DsVWzaowVFjME2YoM1SvEED
Dy2BYzYlaWRdZHDAm/sJaKjFUdAiaSvNcranXyPn0+hy/VBbT/u5MebSGYbdaWKe
B/x0ERxp2ILlcEuU5O4R0w8WQxQ1megNF4Uz4XIQfUk3
-----END CERTIFICATE-----
EOF


function run_tests() { 
   # cp extract_kernel_mod_sig.pl /tmp/
   
   vm_check
   pciid_check
   vbios_check
   
   secure_boot_check
   kernel_image_sig_check
   kernel_mod_sig_check
   # echo "GPU Verification Successful"
   # echo "$EXPECTED_GPUS"
   get_info
}
function write_to_json() {
    cat <<EOF
{
    "PCIID Device": "0x$PCI_DEVICE_ID",
    "PCIID Vendor": "0x$PCI_VENDOR_ID",
    "Subsystem PCIID Device": "0x$SUBSYSTEM_VENDOR_ID",
    "Subsystem PCIID Vendor": "0x$SUBSYSTEM_DEVICE_ID",
    "GPU UUID": "$GPU_UUID",
    "VBIOS": "$VBIOS_VERSION",
    "GPU Name": "$GPU_NAME",
    "VBIOS Integrity": "$VBIOS_INTEGRITY",
    "Kernel Module Check": "$KERNEL_MODULE_CHECK",
    "Secure Boot": "$SECURE_BOOT",
    "Kernel Image Validation": "$KERNEL_IMAGE_CHECK",
    "Virtualization Check": "$VM_CHECK"
}
EOF

}


run_tests
write_to_json
