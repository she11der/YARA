import "pe"

rule SIGNATURE_BASE__Iissample_Nesscan_Twwwscan
{
	meta:
		description = "Disclosed hacktool set (old stuff) - from files iissample.exe, nesscan.exe, twwwscan.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "a710ca8e-54dc-5a98-b173-c87b22af745f"
		date = "2014-11-23"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L2738-L2764"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "6088dd060507f4efa2f4c1770dc746100966e8a7475859918488d7be6c96bc31"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash0 = "7f20962bbc6890bf48ee81de85d7d76a8464b862"
		hash1 = "c0b1a2196e82eea4ca8b8c25c57ec88e4478c25b"
		hash2 = "548f0d71ef6ffcc00c0b44367ec4b3bb0671d92f"

	strings:
		$s0 = "Connecting HTTP Port - Result: " fullword
		$s1 = "No space for command line argument vector" fullword
		$s3 = "Microsoft(July/1999~) http://www.microsoft.com/technet/security/current.asp" fullword
		$s5 = "No space for copy of command line" fullword
		$s7 = "-  Windows NT,2000 Patch Method  - " fullword
		$s8 = "scanf : floating point formats not linked" fullword
		$s12 = "hrdir_b.c: LoadLibrary != mmdll borlndmm failed" fullword
		$s13 = "!\"what?\"" fullword
		$s14 = "%s Port %d Closed" fullword
		$s16 = "printf : floating point formats not linked" fullword
		$s17 = "xxtype.cpp" fullword

	condition:
		all of them
}
