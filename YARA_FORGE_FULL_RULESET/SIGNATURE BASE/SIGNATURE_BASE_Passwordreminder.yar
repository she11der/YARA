rule SIGNATURE_BASE_Passwordreminder
{
	meta:
		description = "Webshells Auto-generated - file PasswordReminder.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "642033ee-4454-5913-8348-4d1579fc0bd8"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L8059-L8070"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "ea49d754dc609e8bfa4c0f95d14ef9bf"
		logic_hash = "f3da5381f5e352c541654d2af918ca8cea8049d137078670dd0538a4d13f676e"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s3 = "The encoded password is found at 0x%8.8lx and has a length of %d."

	condition:
		all of them
}
