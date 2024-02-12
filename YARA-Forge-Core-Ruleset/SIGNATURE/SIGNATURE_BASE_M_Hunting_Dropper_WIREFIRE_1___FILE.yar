rule SIGNATURE_BASE_M_Hunting_Dropper_WIREFIRE_1___FILE
{
	meta:
		description = "This rule detects WIREFIRE, a web shell written in Python that exists as trojanized logic to a component of the pulse secure appliance."
		author = "Mandiant"
		id = "051244f0-00b1-5a4b-8c81-f4ce6f1aa22a"
		date = "2024-01-11"
		modified = "2024-01-12"
		reference = "https://www.mandiant.com/resources/blog/suspected-apt-targets-ivanti-zero-day"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_report_ivanti_mandiant_jan24.yar#L38-L55"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "6de651357a15efd01db4e658249d4981"
		logic_hash = "c389a666bd093cdd7700385da43c8fa58b9f3d899e658c516df0f3aca439401d"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "zlib.decompress(aes.decrypt(base64.b64decode(" ascii
		$s2 = "aes.encrypt(t+('\\x00'*(16-len(t)%16))" ascii
		$s3 = "Handles DELETE request to delete an existing visits data." ascii
		$s4 = "request.data.decode().startswith('GIF'):" ascii
		$s5 = "Utils.api_log_admin" ascii

	condition:
		filesize <10KB and all of them
}