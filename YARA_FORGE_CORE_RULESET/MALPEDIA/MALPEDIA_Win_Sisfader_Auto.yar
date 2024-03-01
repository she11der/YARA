rule MALPEDIA_Win_Sisfader_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "1937373c-a869-5de8-8c47-c30db9548d3e"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sisfader"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.sisfader_auto.yar#L1-L291"
		license_url = "N/A"
		logic_hash = "288baaa87a5a9f6675c09b00537afbaf23a5deab091befb8544155fddb8ada09"
		score = 75
		quality = 73
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
		$sequence_0 = { 85c9 741f 33c0 85c9 }
		$sequence_1 = { e8???????? 85c0 b91d000000 0f44d9 }
		$sequence_2 = { 8906 83f824 723e b824000000 }
		$sequence_3 = { 8b4dfc 51 8b55f8 52 e8???????? 83c408 8945f4 }
		$sequence_4 = { 33d2 b904000000 e8???????? 33c0 83f801 7425 baffffffff }
		$sequence_5 = { 83793000 0f85be000000 8b55fc 8b45f0 }
		$sequence_6 = { 837c245000 7402 eb12 c744245401000000 33c0 }
		$sequence_7 = { c705????????07000000 8b442438 8905???????? c705????????00000000 8b442440 8905???????? c705????????b80b0000 }
		$sequence_8 = { 837c242001 7425 837c242002 7441 837c242003 745d 837c242004 }
		$sequence_9 = { 85c0 752b 8d45f8 c745f882000000 50 8d8618010000 50 }
		$sequence_10 = { 66837c246c2e 7518 0fb74c246e 6685c9 }
		$sequence_11 = { 83790800 745d c745f800000000 eb09 8b55f8 83c201 }
		$sequence_12 = { 746b c744242000000000 eb0a 8b442420 }
		$sequence_13 = { 6a04 e8???????? 83c40c 8b4d0c 51 }
		$sequence_14 = { 8b442448 89442420 837c242001 7402 eb05 e8???????? }
		$sequence_15 = { 8b45f0 83781000 750e 8b4df0 8b510c 0355cc 8955e4 }
		$sequence_16 = { 0fb74c247e 6685c9 0f84cd010000 6683f92e 750f }
		$sequence_17 = { 720b 03f0 eb9c 5f 5e 33c0 5b }
		$sequence_18 = { e8???????? b90e000000 ff15???????? 33c0 e9???????? e9???????? ff15???????? }
		$sequence_19 = { 745d 837c242004 7479 837c242005 0f8480000000 }
		$sequence_20 = { ebbc 8b4dfc 8b5108 52 ff15???????? 83c404 8b45fc }
		$sequence_21 = { 8d8574fdffff 6804010000 50 6a00 ff15???????? 8d8574fdffff }
		$sequence_22 = { 7426 8b4f04 85c9 741f }
		$sequence_23 = { 8139aaeeddff 0f858e000000 8b4104 85c0 }
		$sequence_24 = { 8b45fc 8b08 83792800 7457 }
		$sequence_25 = { 85c9 7513 ffb318020000 ff15???????? 33c0 5b }
		$sequence_26 = { 8b45ac 894610 8b45b0 894614 ff15???????? 66894604 8d45e8 }
		$sequence_27 = { 8b55fc 8b4230 50 ff15???????? 83c404 }
		$sequence_28 = { ba08020000 0f114014 c7400856120000 89580c c700aaeeddff }
		$sequence_29 = { 85c0 7416 0f1f4000 8bc1 83e00f 8a0430 30441124 }

	condition:
		7 of them and filesize <417792
}
