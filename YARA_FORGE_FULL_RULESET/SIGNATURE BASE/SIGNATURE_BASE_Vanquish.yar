rule SIGNATURE_BASE_Vanquish
{
	meta:
		description = "Webshells Auto-generated - file vanquish.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "143e5e46-ffbc-5aee-9f9b-13374a6c3c10"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L7463-L7476"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "684450adde37a93e8bb362994efc898c"
		logic_hash = "223c59d06a9389f380fa29959c54e53a17b53080f704189ae519b9527b2c6384"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s3 = "You cannot delete protected files/folders! Instead, your attempt has been logged"
		$s8 = "?VCreateProcessA@@YGHPBDPADPAU_SECURITY_ATTRIBUTES@@2HKPAX0PAU_STARTUPINFOA@@PAU"
		$s9 = "?VFindFirstFileExW@@YGPAXPBGW4_FINDEX_INFO_LEVELS@@PAXW4_FINDEX_SEARCH_OPS@@2K@Z"

	condition:
		all of them
}
