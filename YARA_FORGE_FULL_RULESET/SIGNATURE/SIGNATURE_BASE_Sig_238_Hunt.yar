import "pe"

rule SIGNATURE_BASE_Sig_238_Hunt
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file hunt.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "5d9d1f99-2f12-51e9-a554-b349e19d00fb"
		date = "2014-11-23"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L1515-L1534"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "f9f059380d95c7f8d26152b1cb361d93492077ca"
		logic_hash = "66d22c4dc2864d61bd485d6840887905f020fce8e19bb976ec09acaa6ed0387c"
		score = 60
		quality = 83
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "Programming by JD Glaser - All Rights Reserved" fullword ascii
		$s3 = "Usage - hunt \\\\servername" fullword ascii
		$s4 = ".share = %S - %S" fullword wide
		$s5 = "SMB share enumerator and admin finder " fullword ascii
		$s7 = "Hunt only runs on Windows NT..." fullword ascii
		$s8 = "User = %S" fullword ascii
		$s9 = "Admin is %s\\%s" fullword ascii

	condition:
		all of them
}
