import "pe"

rule SIGNATURE_BASE_EQGRP_Sploit : FILE
{
	meta:
		description = "EQGRP Toolset Firewall - from files sploit.py, sploit.py"
		author = "Florian Roth (Nextron Systems)"
		id = "9f403965-5fb1-55b2-bef6-65c18e08e58f"
		date = "2016-08-16"
		modified = "2023-12-05"
		reference = "Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp.yar#L1113-L1135"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "083f103dee6b209626c4d790dff0e53af757945ded63409b26bbe143c78e30eb"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "0316d70a5bbf068a7fc791e08e816015d04ec98f088a7ff42af8b9e769b8d1f6"
		hash2 = "0316d70a5bbf068a7fc791e08e816015d04ec98f088a7ff42af8b9e769b8d1f6"

	strings:
		$s1 = "print \"[+] Connecting to %s:%s\" % (self.params.dst['ip'], self.params.dst['port'])" fullword ascii
		$s2 = "@overridable(\"Must be overriden if the target will be touched.  Base implementation should not be called.\")" fullword ascii
		$s3 = "@overridable(\"Must be overriden.  Base implementation should not be called.\")" fullword ascii
		$s4 = "exp.load_vinfo()" fullword ascii
		$s5 = "if not okay and self.terminateFlingOnException:" fullword ascii
		$s6 = "print \"[-] keyboard interrupt before response received\"" fullword ascii
		$s7 = "if self.terminateFlingOnException:" fullword ascii
		$s8 = "print 'Debug info ','='*40" fullword ascii

	condition:
		( uint16(0)==0x2123 and filesize <90KB and 1 of ($s*)) or (4 of them )
}
