rule SIGNATURE_BASE_CN_Honker_Mempodipper2_6 : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file mempodipper2.6.39"
		author = "Florian Roth (Nextron Systems)"
		id = "43a27968-adab-5f27-9b8c-8f0f895f0576"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_tools.yar#L189-L203"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "ba2c79911fe48660898039591e1742b3f1a9e923"
		logic_hash = "1a2c42757199818b94a73b9faff3380911655992ef3214a33a220eac15850c4b"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "objdump -d /bin/su|grep '<exit@plt>'|head -n 1|cut -d ' ' -f 1|sed" ascii

	condition:
		filesize <30KB and all of them
}
