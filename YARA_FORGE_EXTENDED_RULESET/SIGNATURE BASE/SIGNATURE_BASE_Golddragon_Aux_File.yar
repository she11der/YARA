import "pe"

rule SIGNATURE_BASE_Golddragon_Aux_File : FILE
{
	meta:
		description = "Detects export from Gold Dragon - February 2018"
		author = "Florian Roth (Nextron Systems)"
		id = "8f23dec4-e369-500f-a036-32df13e5543e"
		date = "2018-02-03"
		modified = "2023-12-05"
		reference = "https://securingtomorrow.mcafee.com/mcafee-labs/gold-dragon-widens-olympics-malware-attacks-gains-permanent-presence-on-victims-systems/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_golddragon.yar#L31-L44"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "4c5eb04cdafe3a69e584c64b833d8c6d21890660e92cc050bb29798dbcdf5326"
		score = 90
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$x1 = "/////////////////////regkeyenum////////////" ascii

	condition:
		filesize <500KB and 1 of them
}
