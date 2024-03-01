rule SIGNATURE_BASE_Hdconfig
{
	meta:
		description = "Webshells Auto-generated - file HDConfig.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "6f743137-e85a-5298-b51e-c8792e507d28"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L8997-L9012"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "7d60e552fdca57642fd30462416347bd"
		logic_hash = "9001f79db15548cf3ca931d0043d078db7d900ab26093afbf5cd44d0a85800f4"
		score = 60
		quality = 55
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "An encryption key is derived from the password hash. "
		$s3 = "A hash object has been created. "
		$s4 = "Error during CryptCreateHash!"
		$s5 = "A new key container has been created."
		$s6 = "The password has been added to the hash. "

	condition:
		all of them
}
