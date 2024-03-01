rule SIGNATURE_BASE_CN_Honker_Mafix_Root : FILE
{
	meta:
		description = "Script from disclosed CN Honker Pentest Toolset - file root"
		author = "Florian Roth (Nextron Systems)"
		id = "ae08b2e9-4d81-5f15-88d2-e2ace20626bf"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_scripts.yar#L8-L24"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "826778ef9c22177d41698b467586604e001fed19"
		logic_hash = "db54561ba4b9c1bd4d9b183658b98f6fd3165b05c8d6d7f006ae3b5fc96ba549"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "echo \"# vbox (voice box) getty\" >> /tmp/.init1" fullword ascii
		$s1 = "cp /var/log/tcp.log $HOMEDIR/.owned/bex2/snifflog" fullword ascii
		$s2 = "if [ -f /sbin/xlogin ]; then" fullword ascii

	condition:
		filesize <96KB and all of them
}
