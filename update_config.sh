#!/bin/bash

# Function to display script usage
function print_usage() {
  cat <<EOF
USAGE:
  ./update_config.sh <Mode> [<ServicesEnabled>] [<NumberCyInstances>] [<NumProcesses>] [<LimitDevAccess>]

DESCRIPTION:
   Update the QAT device configuration file based on the provided input or default settings for either multi-process or multi-thread mode.
   This step is applicable only for the Out-of-Tree (OOT) driver, as the in-tree driver does not require configuration files and is instead
   managed through policy settings located in `/etc/sysconfig/qat`.

ARGUMENTS:
  -h or -help:
    Print usage help.

  <Mode>:
    multi_process: Configure for multi-process mode.
    multi_thread: Configure for multi-thread mode.

  <ServicesEnabled>:
    QAT Gen4 devices (4xxx, 401x, 402x): 'asym;sym', 'asym', 'sym', 'asym;dc', or 'sym;dc' if compression co-exists.
    Other lower QAT Gen (37c8): 'cy'.

  <NumberCyInstances>:
    Number of CyInstances to configure in the driver configuration file.

  <NumProcesses>:
    Number of processes to configure in the driver configuration file.

  <LimitDevAccess>:
    LimitDevAccess configuration in the driver configuration file. Acceptable values: [0, 1].

EXAMPLES:
  ./update_config.sh multi_process
  ./update_config.sh multi_thread
  ./update_config.sh multi_process asym 1 64 0
EOF
}

# Print help
if [[ "$1" == "-h" || "$1" == "-help" ]]; then
  print_usage
  exit 0
fi

# Validate mode and set default
if [[ "$1" != "multi_process" && "$1" != "multi_thread" ]]; then
  echo "Invalid mode. Defaulting to multi_process mode."
  mode="multi_process"
else
  mode="$1"
fi

# Determine OS and set variables
if [[ "$OSTYPE" == "FreeBSD" || "$OSTYPE" =~ "freebsd" ]]; then
  sed_command="gsed"
  numC62xDevice=`pciconf -lbvec | egrep "8086" | egrep -c "37c8"`
  num4xxxDevice=`pciconf -lbvec | egrep "8086" | egrep -c "4940|4942|4944"`
else
  sed_command="sed"
  num4xxxDevice=`lspci -vnd 8086: | egrep -c "4940|4942|4944"`
  num420xxDevice=`lspci -vnd 8086: | egrep -c "4946"`
  numC4xxxDevice=`lspci -vnd 8086: | grep -c "18a0"`
  num200xxDevice=`lspci -vnd 8086: | grep -c "18ee"`
  numC62xDevice=`lspci -vnd 8086: | grep -c "37c8"`
  num4xxxDeviceVF=`lspci -vnd 8086: | egrep -c "4941|4943|4945"`
  num420xxDeviceVF=`lspci -vnd 8086: | egrep -c "4947"`
fi

# QAT Device specific configuration
if [[ "$num4xxxDevice" -gt 0 ]]; then
  dev_type="4xxx"
  config_file="4xxx_dev0.conf"
  qat_version="QAT2.0"
  num_devices=$num4xxxDevice
  service_default="asym;sym"
  cy_default="4"
  process_default="8"
  limit_dev_default="1"
  cy_default=$([[ "$mode" == "multi_thread" ]] && echo "12" || echo "4")
  process_default=$([[ "$mode" == "multi_thread" ]] && echo "1" || echo "8")
  limit_dev_default=$([[ "$mode" == "multi_thread" ]] && echo "0" || echo "1")
  if [[ "$num4xxxDeviceVF" -gt 0 ]]; then
    vf_config_file="4xxxvf_dev0.conf"
    $sed_command -i "s/ServicesEnabled.*/ServicesEnabled = asym;sym/" "/etc/$vf_config_file"
    $sed_command -i "s/\[SSL\]/[SHIM]/g" "/etc/$vf_config_file"
    $sed_command -i "/\[SHIM\]/{N;s/\[SHIM\]\nNumberCyInstances.*/[SHIM]\nNumberCyInstances = 1/}" "/etc/$vf_config_file"
    $sed_command -i "s/NumberDcInstances.*/NumberDcInstances = 0/" "/etc/$vf_config_file"
    $sed_command -i "s/LimitDevAccess.*/LimitDevAccess = 1/" "/etc/$vf_config_file"
    for(( i=1; i<$num4xxxDeviceVF; i++ ))
    do
       cp -f /etc/$vf_config_file /etc/$dev_type'vf_dev'$i.conf
    done
  fi
elif [[ "$num420xxDevice" -gt 0 ]]; then
  dev_type="420xx"
  config_file="420xx_dev0.conf"
  qat_version="QAT2.2"
  num_devices=$num420xxDevice
  service_default="asym;sym"
  cy_default=$([[ "$mode" == "multi_thread" ]] && echo "12" || echo "1")
  process_default=$([[ "$mode" == "multi_thread" ]] && echo "1" || echo "32")
  limit_dev_default=$([[ "$mode" == "multi_thread" ]] && echo "0" || echo "1")
  if [[ "$num420xxDeviceVF" -gt 0 ]]; then
    vf_config_file="420xxvf_dev0.conf"
    $sed_command -i "s/ServicesEnabled.*/ServicesEnabled = asym;sym/" "/etc/$vf_config_file"
    $sed_command -i "s/\[SSL\]/[SHIM]/g" "/etc/$vf_config_file"
    $sed_command -i "/\[SHIM\]/{N;s/\[SHIM\]\nNumberCyInstances.*/[SHIM]\nNumberCyInstances = 1/}" "/etc/$vf_config_file"
    $sed_command -i "s/NumberDcInstances.*/NumberDcInstances = 0/" "/etc/$vf_config_file"
    $sed_command -i "s/LimitDevAccess.*/LimitDevAccess = 1/" "/etc/$vf_config_file"
    for(( i=1; i<$num420xxDeviceVF; i++ ))
    do
       cp -f /etc/$vf_config_file /etc/$dev_type'vf_dev'$i.conf
    done
  fi
elif [[ "$numC4xxxDevice" -gt 0 ]]; then
  dev_type="c4xxx"
  config_file="c4xxx_dev0.conf"
  qat_version="QAT1.8"
  num_devices=$numC4xxxDevice
  service_default="cy"
  cy_default=$([[ "$mode" == "multi_thread" ]] && echo "2" || echo "1")
  process_default=$([[ "$mode" == "multi_thread" ]] && echo "1" || echo "16")
  limit_dev_default=$([[ "$mode" == "multi_thread" ]] && echo "0" || echo "1")
  $sed_command -i 's/NumCyAccelUnits.*/NumCyAccelUnits = 6/' "/etc/$config_file"
  $sed_command -i 's/NumDcAccelUnits.*/NumDcAccelUnits = 0/' "/etc/$config_file"
elif [[ "$num200xxDevice" -gt 0 ]]; then
  dev_type="200xx"
  config_file="200xx_dev0.conf"
  qat_version="QAT1.72"
  num_devices=$num200xxDevice
  service_default="cy"
  cy_default=$([[ "$mode" == "multi_thread" ]] && echo "8" || echo "1")
  process_default=$([[ "$mode" == "multi_thread" ]] && echo "1" || echo "16")
  limit_dev_default=$([[ "$mode" == "multi_thread" ]] && echo "0" || echo "1")
elif [[ "$numC62xDevice" -gt 0 ]]; then
  dev_type="c6xx"
  config_file="c6xx_dev0.conf"
  qat_version="QAT1.7"
  num_devices=$numC62xDevice
  service_default="cy"
  cy_default=$([[ "$mode" == "multi_thread" ]] && echo "8" || echo "1")
  process_default=$([[ "$mode" == "multi_thread" ]] && echo "1" || echo "16")
  limit_dev_default=$([[ "$mode" == "multi_thread" ]] && echo "0" || echo "1")
else
  echo "Unsupported QAT Device in the script"
  exit 1
fi

# Display configuration summary
echo "====================================="
echo "QAT Device Version   : $qat_version"
echo "Num QAT Devices      : $num_devices"
echo "Device Type          : $dev_type"
echo "Config file          : $config_file"
echo "Mode                 : $mode"
echo "====================================="

# Set configuration parameters
service_enabled="${2:-$service_default}"
cy_instance="${3:-$cy_default}"
num_process="${4:-$process_default}"
limit_dev="${5:-$limit_dev_default}"

# Function to generate configuration file
function generate_config() {
  local config_file=$1
  local cy_instance=$2
  local num_process=$3
  local limit_dev=$4

  if [[ ! -e "/etc/$config_file" ]]; then
    echo "$config_file does not exist. Check if OOT driver is installed!"
    exit 1
  fi

  echo "Generating config file $config_file..."
  $sed_command -i "s/ServicesEnabled.*/ServicesEnabled = $service_enabled/" "/etc/$config_file"
  $sed_command -i "s/\[SSL\]/[SHIM]/g" "/etc/$config_file"
  $sed_command -i "/\[SHIM\]/{N;s/\[SHIM\]\nNumberCyInstances.*/[SHIM]\nNumberCyInstances = $cy_instance/}" "/etc/$config_file"
  $sed_command -i "s/NumberDcInstances.*/NumberDcInstances = 0/" "/etc/$config_file"
  $sed_command -i "s/NumProcesses.*/NumProcesses = $num_process/" "/etc/$config_file"
  $sed_command -i "s/LimitDevAccess.*/LimitDevAccess = $limit_dev/" "/etc/$config_file"

  # Remove existing crypto instances
  local start_string="KERNEL"
  $sed_command -i "/$start_string/,\$d" "/etc/$config_file"
  $sed_command -i "s/ServicesEnabled.*/ServicesEnabled = $service_enabled/" "/etc/$config_file"
  cat <<EOF >>"/etc/$config_file"
[KERNEL]
NumberCyInstances = 0
NumberDcInstances = 0

##############################################
# User Process Instance Section
##############################################
[SHIM]
NumberCyInstances = ${cy_instance}
NumberDcInstances = 0
NumProcesses = ${num_process}
LimitDevAccess = ${limit_dev/}
EOF

  # Add new crypto instances
  for ((i = 0; i < $cy_instance; i++)); do
  cat <<EOF >>"/etc/$config_file"

# Crypto - User instance #$i
Cy${i}Name = "UserCY${i}"
Cy${i}IsPolled = 1
# List of core affinities
Cy${i}CoreAffinity = $i
EOF
  done
}

generate_config "$config_file" "$cy_instance" "$num_process" "$limit_dev"

for(( i=1; i<$num_devices; i++ ))
do 
   cp -f /etc/$config_file /etc/$dev_type'_dev'$i.conf
done    

# Restart QAT services
if [[  "$num4xxxDeviceVF" -gt 0 || "$num420xxDeviceVF" -gt 0 ]]; then
  service qat restart
else
  adf_ctl restart
fi

echo "QAT device configuration files have been successfully updated in /etc"
