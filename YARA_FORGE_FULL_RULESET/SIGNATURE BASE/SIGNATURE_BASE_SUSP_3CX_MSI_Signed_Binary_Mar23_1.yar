import "pe"

rule SIGNATURE_BASE_SUSP_3CX_MSI_Signed_Binary_Mar23_1 : FILE
{
	meta:
		description = "Detects 3CX MSI installers signed with a known compromised certificate and signed in a time frame in which other known malicious binaries have been signed"
		author = "Florian Roth (Nextron Systems)"
		id = "15d6d8ca-6982-5095-9879-ce97269a71c6"
		date = "2023-03-29"
		modified = "2023-12-05"
		reference = "https://www.reddit.com/r/crowdstrike/comments/125r3uu/20230329_situational_awareness_crowdstrike/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_mal_3cx_compromise_mar23.yar#L141-L166"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "b0fa9821a02803473ce8139b19d005968b03c9765cff5b9ae5428a259d88cc9f"
		score = 60
		quality = 85
		tags = "FILE"
		hash1 = "aa124a4b4df12b34e74ee7f6c683b2ebec4ce9a8edcf9be345823b4fdcf5d868"
		hash2 = "59e1edf4d82fae4978e97512b0331b7eb21dd4b838b850ba46794d9c7a2c0983"

	strings:
		$a1 = { 84 10 0C 00 00 00 00 00 C0 00 00 00 00 00 00 46 }
		$sc1 = { 1B 66 11 DF 9C 9A 4D 6E CC 8E D5 0C 9B 91 78 73 }
		$s1 = "3CX Ltd1"
		$s2 = "202303"

	condition:
		uint16(0)==0xcfd0 and $a1 and $sc1 and ($s1 in ( filesize -20000.. filesize ) and $s2 in ( filesize -20000.. filesize ))
}
