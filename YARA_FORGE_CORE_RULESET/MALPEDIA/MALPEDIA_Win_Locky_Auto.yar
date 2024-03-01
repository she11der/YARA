rule MALPEDIA_Win_Locky_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "0065ec05-3bad-56a6-868c-9fbbe2e6de6d"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.locky"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.locky_auto.yar#L1-L170"
		license_url = "N/A"
		logic_hash = "3ed4a85dfe440bb226db6c3cc6e1aa5c521449c7aa69fbc084d35b1292d156c0"
		score = 75
		quality = 75
		tags = "FILE"
		version = "1"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"

	strings:
		$sequence_0 = { 89b560ffffff 898568ffffff ffd7 8bf8 897de0 3bfb }
		$sequence_1 = { 8b4db8 3975cc 7303 8d4db8 8b45d4 3975e8 }
		$sequence_2 = { 50 50 50 894de8 8b4d08 }
		$sequence_3 = { 8d459c 50 8d45b8 50 e8???????? 59 59 }
		$sequence_4 = { 46 3bf0 7621 8bc8 d1e9 ba49922409 }
		$sequence_5 = { 8bc6 03c1 3810 7412 83ff10 7204 }
		$sequence_6 = { 837e1410 8b4610 7202 8b36 50 56 8d45f0 }
		$sequence_7 = { 83c9ff 8bf0 51 e8???????? 40 50 }
		$sequence_8 = { 03d3 5b c21000 e9???????? 8bff 55 8bec }
		$sequence_9 = { 6a44 90 e9???????? 90 }
		$sequence_10 = { 5d 90 ebf6 90 }
		$sequence_11 = { 83c40c e9???????? 90 8d00 }
		$sequence_12 = { 66ab e9???????? 90 8d36 }
		$sequence_13 = { ff15???????? e9???????? 90 50 90 }
		$sequence_14 = { 66ab 90 e9???????? 8d36 }
		$sequence_15 = { 5e c21000 8bff 55 8bec 33c0 8b4d08 }

	condition:
		7 of them and filesize <1122304
}
