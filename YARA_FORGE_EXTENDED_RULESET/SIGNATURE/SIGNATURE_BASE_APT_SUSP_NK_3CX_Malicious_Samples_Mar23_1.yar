import "pe"

rule SIGNATURE_BASE_APT_SUSP_NK_3CX_Malicious_Samples_Mar23_1
{
	meta:
		description = "Detects indicator (event name) found in samples related to 3CX compromise"
		author = "Florian Roth (Nextron Systems)"
		id = "b233846a-19df-579b-a674-233d66824008"
		date = "2023-03-30"
		modified = "2023-12-05"
		reference = "https://www.sentinelone.com/blog/smoothoperator-ongoing-campaign-trojanizes-3cx-software-in-software-supply-chain-attack/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_mal_3cx_compromise_mar23.yar#L216-L232"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "6ab8a4ac184eaba6eb56bfc49d6fa03f9b0877d75294aa9a242e9ac96482fab0"
		score = 70
		quality = 85
		tags = ""
		hash1 = "7986bbaee8940da11ce089383521ab420c443ab7b15ed42aed91fd31ce833896"
		hash2 = "59e1edf4d82fae4978e97512b0331b7eb21dd4b838b850ba46794d9c7a2c0983"
		hash3 = "aa124a4b4df12b34e74ee7f6c683b2ebec4ce9a8edcf9be345823b4fdcf5d868"
		hash4 = "c485674ee63ec8d4e8fde9800788175a8b02d3f9416d0e763360fff7f8eb4e02"

	strings:
		$a1 = "AVMonitorRefreshEvent" wide fullword

	condition:
		1 of them
}
