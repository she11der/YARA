rule SIGNATURE_BASE_SUSP_Recon_Outputs_Jun20_1 : FILE
{
	meta:
		description = "Detects outputs of many different commands often used for reconnaissance purposes"
		author = "Florian Roth (Nextron Systems)"
		id = "ec3759aa-212f-52ce-9f38-636accd35749"
		date = "2020-06-04"
		modified = "2023-12-05"
		reference = "https://securelist.com/cycldek-bridging-the-air-gap/97157/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_recon_indicators.yar#L52-L74"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "652b28bfb45a11eaaee198c76560c1f55edc5b32c5394e606bb5426551260f24"
		score = 60
		quality = 85
		tags = "FILE"

	strings:
		$s1 = ". . . . : Yes" ascii
		$s2 = "with 32 bytes of data:" ascii
		$s3 = "ff-ff-ff-ff-ff-ff     static" ascii
		$s4 = "  TCP    0.0.0.0:445" ascii
		$s5 = "System Idle Process" ascii

	condition:
		filesize <150KB and 4 of them
}
