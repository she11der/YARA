rule SIGNATURE_BASE_APT_MAL_RANSOM_Vicesociety_Polyvice_Jan23_1 : FILE
{
	meta:
		description = "Detects NTRU-ChaChaPoly (PolyVice) malware used by Vice Society"
		author = "Florian Roth (Nextron Systems)"
		id = "e450407c-6c21-56bf-aedf-8e7f3890abe2"
		date = "2023-01-12"
		modified = "2023-01-13"
		reference = "https://www.sentinelone.com/labs/custom-branded-ransomware-the-vice-society-group-and-the-threat-of-outsourced-development/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_ransom_vicesociety_dec22.yar#L2-L31"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "3c7b76a693e5666515afee5c819b21e119ce5f1b0be675252673e6a24251ce8d"
		score = 75
		quality = 60
		tags = "FILE"
		hash1 = "326a159fc2e7f29ca1a4c9a64d45b76a4a072bc39ba864c49d804229c5f6d796"
		hash2 = "8c8cb887b081e0d92856fb68a7df0dabf0b26ed8f0a6c8ed22d785e596ce87f4"
		hash3 = "9d9e949ecd72d7a7c4ae9deae4c035dcae826260ff3b6e8a156240e28d7dbfef"

	strings:
		$x1 = "C:\\Users\\root\\Desktop\\niX\\CB\\libntru\\" ascii
		$s1 = "C:\\Users\\root" ascii fullword
		$s2 = "#DBG: target = %s" ascii fullword
		$s3 = "# ./%s [-p <path>]/[-f <file> ] [-e <enc.extension>] [-m <requirements file name>]" ascii fullword
		$s4 = "### ################# ###" ascii fullword
		$op1 = { 89 ca 41 01 fa 89 ef 8b 6c 24 24 44 89 c9 09 d1 44 31 e6 89 c8 }
		$op2 = { bd 02 00 00 00 29 cd 48 0f bf d1 8b 44 46 02 01 44 53 02 8d 54 0d 00 83 c1 02 48 0f bf c2 }
		$op3 = { 48 29 c4 4c 8d 74 24 30 4c 89 f1 e8 46 3c 00 00 84 c0 41 89 c4 0f 85 2b 02 00 00 0f b7 45 f2 }

	condition:
		uint16(0)==0x5a4d and filesize <400KB and (1 of ($x*) or 2 of them ) or 4 of them
}
