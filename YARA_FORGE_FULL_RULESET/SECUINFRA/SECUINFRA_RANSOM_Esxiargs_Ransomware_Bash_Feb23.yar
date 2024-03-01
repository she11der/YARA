rule SECUINFRA_RANSOM_Esxiargs_Ransomware_Bash_Feb23
{
	meta:
		description = "Detects the ESXiArgs Ransomware encryption bash script"
		author = "SECUINFRA Falcon Team (@SI_FalconTeam)"
		id = "dafcb312-bad2-5dcc-8260-80d09e11853b"
		date = "2023-02-07"
		modified = "2023-02-07"
		reference = "https://secuinfra.com/en/techtalk/hide-your-hypervisor-analysis-of-esxiargs-ransomware"
		source_url = "https://github.com/SIFalcon/Detection/blob/2d7c66d7d16c7541bf2a9a83a7a6d334364a26fd/Yara/Malware/RANSOM_ESXiArgs_Ransomware_Bash_Feb23.yar#L1-L45"
		license_url = "N/A"
		logic_hash = "e9838fd86e25c434f419dcc8d37a56f4f83c38930b0558181585bbfe77cd1baf"
		score = 75
		quality = 70
		tags = ""
		tlp = "CLEAR"

	strings:
		$bash = "#!/bin/sh"
		$wait = "Waiting for task' completion..."
		$comment0 = "## SSH HI"
		$comment1 = "## CHANGE CONFIG"
		$comment2 = "## STOP VMX"
		$kill0 = "echo \"KILL VMX\""
		$kill1 = "kill -9 $(ps | grep vmx | awk '{print $2}')"
		$index = "$path_to_ui/index1.html"
		$ext0 = ".vmdk"
		$ext1 = ".vmx"
		$ext2 = ".vmxf"
		$ext3 = ".vmsd"
		$ext4 = ".vmsn"
		$ext5 = ".vswp"
		$ext6 = ".vmss"
		$ext7 = ".nvram"
		$ext8 = ".vmem"
		$clean0 = "/bin/rm -f $CLEAN_DIR\"encrypt\" $CLEAN_DIR\"nohup.out\" $CLEAN_DIR\"index.html\" $CLEAN_DIR\"motd\" $CLEAN_DIR\"public.pem\" $CLEAN_DIR\"archieve.zip\""
		$clean1 = "/bin/echo '' > /etc/rc.local.d/local.sh"

	condition:
		$bash and $wait and any of ($comment*) and 2 of ($kill*) and $index and 4 of ($ext*) and 2 of ($clean*)
}
