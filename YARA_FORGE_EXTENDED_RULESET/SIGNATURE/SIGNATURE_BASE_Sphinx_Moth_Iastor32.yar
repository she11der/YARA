rule SIGNATURE_BASE_Sphinx_Moth_Iastor32 : FILE
{
	meta:
		description = "sphinx moth threat group file iastor32.exe"
		author = "Kudelski Security - Nagravision SA"
		id = "5688c598-ea18-578f-bb8a-3729c0502af5"
		date = "2015-08-06"
		modified = "2023-12-05"
		reference = "www.kudelskisecurity.com"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_sphinx_moth.yar#L47-L59"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "056949677654a88fb430c988939006dacfefdabbe12824936a01e5aabbb73441"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s0 = "MIIEpQIBAAKCAQEA4lSvv/W1Mkz38Q3z+EzJBZRANzKrlxeE6/UXWL67YtokF2nN" fullword ascii
		$s1 = "iAeS3CCA4wli6+9CIgX8SAiXd5OezHvI1jza61z/flsqcC1IP//gJVt16nRx3s9z" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <2000KB and all of them
}
