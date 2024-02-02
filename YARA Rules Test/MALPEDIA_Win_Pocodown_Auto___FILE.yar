rule MALPEDIA_Win_Pocodown_Auto___FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "57027d9b-6e81-5ca8-a0ac-bbfd288eda02"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.pocodown"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.pocodown_auto.yar#L1-L101"
		license_url = "N/A"
		logic_hash = "d2d2c3510515a24653939603c26fb696816a72e2a82e1c859f658b0238b45291"
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
		$sequence_0 = { 8b84248c000000 ffc8 898424a0010000 c784248800000000000000 ba01000000 488b8c24e0010000 }
		$sequence_1 = { 8b84248c000000 ffc8 8984248c000000 83bc248c00000007 0f875d010000 486384248c000000 }
		$sequence_2 = { 8b842490000000 25ff000000 488b4c2430 884101 }
		$sequence_3 = { 8b84248c020000 8944244c 488b8c2420030000 e8???????? }
		$sequence_4 = { 8b842490000000 2500040000 85c0 740a c744245000000000 eb0a 8b442448 }
		$sequence_5 = { 8b84248c020000 448bc0 ba5c000000 488d8c24f0010000 e8???????? }
		$sequence_6 = { 8b84248c020000 448bc0 488d9424f0010000 488d8c24a0020000 e8???????? }
		$sequence_7 = { 8b842490000000 39442420 0f83e0000000 488d442438 41b808000000 488b542440 }

	condition:
		7 of them and filesize <6703104
}