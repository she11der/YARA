rule VOLEXITY_Cf_Office_Win_Macro_Lazarus_Jeus_B : Lazarus
{
	meta:
		description = "Detects macros used by the Lazarus threat actor to distribute AppleJeus."
		author = "threatintel@volexity.com"
		id = "ac4d4e82-e29f-5134-999d-b8dcef59d285"
		date = "2022-11-03"
		modified = "2022-12-01"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/ae4bcf3413927d976bf3f8ee107bd928c575aded/2022/2022-12-01 Buyer Beware - Fake Cryptocurrency Applications Serving as Front for AppleJeus Malware/yara.yar#L85-L104"
		license_url = "https://github.com/volexity/threat-intel/blob/ae4bcf3413927d976bf3f8ee107bd928c575aded/LICENSE.txt"
		logic_hash = "e55199e6ad26894f98e930cd4716127ee868872d08ada1c44675e4db1ec27894"
		score = 75
		quality = 80
		tags = ""
		hash1 = "17e6189c19dedea678969e042c64de2a51dd9fba69ff521571d63fd92e48601b"
		memory_suitable = 0
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$a1 = ", vbDirectory) = \"\" Then" ascii
		$a2 = ".Caption & " ascii
		$a3 = ".nodeTypedValue" ascii
		$a4 = ".Application.Visible = False" ascii
		$a5 = " MkDir (" ascii

	condition:
		all of ($a*)
}
