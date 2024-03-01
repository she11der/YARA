import "pe"

rule SIGNATURE_BASE_EQGRP_EPBA : FILE
{
	meta:
		description = "EQGRP Toolset Firewall - file EPBA.script"
		author = "Florian Roth (Nextron Systems)"
		id = "5159c2f4-20b7-590d-b216-b3468c26e459"
		date = "2016-08-16"
		modified = "2023-12-05"
		reference = "Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp.yar#L607-L626"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "c483efdcfbb0dd8602a552b519d3aa52fca12549c0ec1660d813a2a1da66c3a6"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "53e1af1b410ace0934c152b5df717d8a5a8f5fdd8b9eb329a44d94c39b066ff7"

	strings:
		$x1 = "./epicbanana_2.0.0.1.py -t 127.0.0.1 --proto=ssh --username=cisco --password=cisco --target_vers=asa804 --mem=NA -p 22 " fullword ascii
		$x2 = "-t TARGET_IP, --target_ip=TARGET_IP -- Either 127.0.0.1 or Win Ops IP" fullword ascii
		$x3 = "./bride-1100 --lp 127.0.0.1 --implant 127.0.0.1 --sport RHP --dport RHP" fullword ascii
		$x4 = "--target_vers=TARGET_VERS    target Pix version (pix712, asa804) (REQUIRED)" fullword ascii
		$x5 = "-p DEST_PORT, --dest_port=DEST_PORT defaults: telnet=23, ssh=22 (optional) - Change to LOCAL redirect port" fullword ascii
		$x6 = "this operation is complete, BananaGlee will" fullword ascii
		$x7 = "cd /current/bin/FW/BGXXXX/Install/LP" fullword ascii

	condition:
		( uint16(0)==0x2023 and filesize <7KB and 1 of ($x*)) or (3 of them )
}
