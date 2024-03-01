rule SIGNATURE_BASE_Genhash_Genhash : FILE
{
	meta:
		description = "Auto-generated rule - file genhash.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "bec3c014-df3b-5ac0-9501-9b648856e02b"
		date = "2015-07-10"
		modified = "2023-12-05"
		reference = "http://www.coresecurity.com/corelabs-research/open-source-tools/pass-hash-toolkit"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_passthehashtoolkit.yar#L56-L74"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "113df11063f8634f0d2a28e0b0e3c2b1f952ef95bad217fd46abff189be5373f"
		logic_hash = "fe1ebe7ea94351610e0042eab020d155cbab26d790477909467c9b5a827fb6d6"
		score = 80
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "genhash.exe <password>" fullword ascii
		$s3 = "Password: %s" fullword ascii
		$s4 = "%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X" fullword ascii
		$s5 = "This tool generates LM and NT hashes." fullword ascii
		$s6 = "(hashes format: LM Hash:NT hash)" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <200KB and 2 of them
}
