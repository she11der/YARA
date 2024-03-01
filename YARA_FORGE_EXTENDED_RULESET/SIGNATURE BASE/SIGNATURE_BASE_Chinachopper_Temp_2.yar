rule SIGNATURE_BASE_Chinachopper_Temp_2 : FILE
{
	meta:
		description = "Chinese Hacktool Set - file temp.php"
		author = "Florian Roth (Nextron Systems)"
		id = "3952ed2b-fb27-5c45-9cd7-b7a300b37c0e"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_webshells.yar#L346-L359"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "604a4c07161ce1cd54aed5566e5720161b59deee"
		logic_hash = "1b6d840797afcdbf7c72836557dbd486780c760471e79133810346c301cca80b"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "@eval($_POST[strtoupper(md5(gmdate(" ascii

	condition:
		filesize <150 and all of them
}
