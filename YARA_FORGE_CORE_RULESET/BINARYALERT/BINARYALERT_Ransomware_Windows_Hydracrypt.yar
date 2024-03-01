rule BINARYALERT_Ransomware_Windows_Hydracrypt
{
	meta:
		description = "HydraCrypt encrypts a victim’s files and appends the filenames with the extension “hydracrypt_ID_*"
		author = "@fusionrace"
		id = "9ebf205e-b6a9-55a3-b0c3-9b088790dc9a"
		date = "2017-08-11"
		modified = "2017-08-11"
		reference = "https://securingtomorrow.mcafee.com/mcafee-labs/hydracrypt-variant-of-ransomware-distributed-by-angler-exploit-kit/"
		source_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/rules/public/ransomware/windows/ransomware_windows_hydracrypt.yara#L1-L16"
		license_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/LICENSE"
		hash = "08b304d01220f9de63244b4666621bba"
		logic_hash = "3ecb3e6c269f4145e60b0e7bb0e896120ceb2db2123f847bf4bdf5d4490467d5"
		score = 75
		quality = 80
		tags = ""

	strings:
		$u0 = "oTraining" fullword ascii wide
		$u1 = "Stop Training" fullword ascii wide
		$u2 = "Play \"sound.wav\"" fullword ascii wide
		$u3 = "&Start Recording" fullword ascii wide
		$u4 = "7About record" fullword ascii wide

	condition:
		all of them
}
