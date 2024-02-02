rule SIGNATURE_BASE_HKTL_Redmimicry_Winntiloader
{
	meta:
		description = "matches the Winnti 'Cooper' loader version used for the RedMimicry breach emulation"
		author = "mirar@chaosmail.org"
		id = "a8be1377-faa0-560d-a12c-0369b1f91180"
		date = "2020-06-22"
		modified = "2023-01-10"
		reference = "https://redmimicry.com"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/gen_redmimicry.yar#L28-L59"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "d8ef457ac41a7c45cc7e97330bdd3de12eb3391c03d0a6a87ddc669c841c325d"
		score = 75
		quality = 85
		tags = ""
		sharing = "tlp:white"

	strings:
		$s0 = "Cooper" ascii fullword
		$s1 = "stone64.dll" ascii fullword
		$decoding_loop = { 49 63 D0 43 8D 0C 01 41 FF C0 42 32 0C 1A 0F B6 C1 C0 E9 04 C0 E0 04 02 C1 42 88 04 1A 44 3B 03 72 DE }

	condition:
		all of them
}