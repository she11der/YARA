rule BINARYALERT_Ransomware_Windows_Petya_Variant_Bitcoin
{
	meta:
		description = "Petya Ransomware new variant June 2017 using ETERNALBLUE: Bitcoin"
		author = "@fusionrace"
		id = "82d6ecc5-7c90-5d50-90ff-f54f8d87685d"
		date = "2017-08-11"
		modified = "2017-08-11"
		reference = "https://gist.github.com/vulnersCom/65fe44d27d29d7a5de4c176baba45759"
		source_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/rules/public/ransomware/windows/ransomware_windows_petya_variant_bitcoin.yara#L1-L13"
		license_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/LICENSE"
		hash = "71b6a493388e7d0b40c83ce903bc6b04"
		logic_hash = "9a5e183aa8e1387e76d5df4e967943b730ba780b6758af3ef23e21bb9e4ce3a6"
		score = 75
		quality = 80
		tags = ""

	strings:
		$s1 = "MIIBCgKCAQEAxP/VqKc0yLe9JhVqFMQGwUITO6WpXWnKSNQAYT0O65Cr8PjIQInTeHkXEjfO2n2JmURWV/uHB0ZrlQ/wcYJBwLhQ9EqJ3iDqmN19Oo7NtyEUmbYmopcq+YLIBZzQ2ZTK0A2DtX4GRKxEEFLCy7vP12EYOPXknVy/+mf0JFWixz29QiTf5oLu15wVLONCuEibGaNNpgq+CXsPwfITDbDDmdrRIiUEUw6o3pt5pNOskfOJbMan2TZu6zfhzuts7KafP5UA8/0Hmf5K3/F9Mf9SE68EZjK+cIiFlKeWndP0XfRCYXI9AJYCeaOu7CXF6U0AVNnNjvLeOn42LHFUK4o6JwIDAQAB" fullword wide

	condition:
		$s1
}
