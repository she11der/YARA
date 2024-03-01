rule SIGNATURE_BASE_APT_SH_Esxi_Backdoor_Dec22 : FILE
{
	meta:
		description = "Detects malicious script found on ESXi servers"
		author = "Florian Roth"
		id = "983ac20c-2e61-5365-8849-b3aeb999f909"
		date = "2022-12-14"
		modified = "2023-12-05"
		reference = "https://blogs.juniper.net/en-us/threat-research/a-custom-python-backdoor-for-vmware-esxi-servers"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/mal_ransom_esxi_attacks_feb23.yar#L73-L87"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "155a90a6c55b99285555634d91a66fca9c7e7297f05314fa4d6ce1d84257ee11"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$x1 = "mv /bin/hostd-probe.sh /bin/hostd-probe.sh.1" ascii fullword
		$x2 = "/bin/nohup /bin/python -u /store/packages/vmtools.py" ascii
		$x3 = "/bin/rm /bin/hostd-probe.sh.1"

	condition:
		filesize <10KB and 1 of them
}
