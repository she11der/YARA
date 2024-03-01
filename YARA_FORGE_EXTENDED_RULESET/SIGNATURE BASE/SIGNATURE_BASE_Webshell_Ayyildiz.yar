rule SIGNATURE_BASE_Webshell_Ayyildiz : FILE
{
	meta:
		description = "Detects Webshell"
		author = "Florian Roth (Nextron Systems)"
		id = "cc752958-eb6c-5185-b94c-5fcec833924d"
		date = "2016-01-11"
		modified = "2023-12-05"
		reference = "https://github.com/nikicat/web-malware-collection"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L9456-L9475"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "8441b7d730e337e002eeb7ae8f489e405409ddbe62f45bbc9a74c935d1d9fe66"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "0e25aec0a9131e8c7bd7d5004c5c5ffad0e3297f386675bccc07f6ea527dded5"
		hash2 = "9c43aada0d5429f8c47595f79a7cdd5d4eb2ba5c559fb5da5a518a6c8c7c330a"
		hash3 = "2ebf3e5f5dde4a27bbd60e15c464e08245a35d15cc370b4be6b011aa7a46eaca"
		hash4 = "77a63b26f52ba341dd2f5e8bbf5daf05ebbdef6b3f7e81cec44ce97680e820f9"
		hash5 = "61c4fcb6e788c0dffcf0b672ae42b1676f8a9beaa6ec7453fc59ad821a4a8127"

	strings:
		$s0 = "echo \"<option value=\\\"\". strrev(substr(strstr(strrev($work_dir), \"/\"), 1)) .\"\\\">Parent Directory</option>\\n\";" fullword ascii
		$s1 = "echo \"<option value=\\\"$work_dir\\\" selected>Current Directory</option>\\n\";" fullword ascii

	condition:
		filesize <112KB and all of them
}
