#!/usr/bin/env fish

set all_ok true

for i in (seq 1 8)
    set cfg "test_config$i.json"
    set in_file "test_in$i"
    set exp_file "exp$i"
    set out_file (mktemp)

    if not ./cipher_cli encrypt "$cfg" "$in_file" "$out_file"
        echo "HIBA [Teszt $i]: A ./cipher_cli futása hibával leállt ($cfg)"
        set all_ok false
        rm -f "$out_file"
        continue
    end

    set exp_size (stat -c %s "$exp_file")

    if cmp -s -n "$exp_size" "$out_file" "$exp_file"
        echo "OK [Teszt $i]: $cfg -> pontos egyezés ($exp_size bájt)"
    else
        echo "HIBA [Teszt $i]: Eltérés a kimenet és az $exp_file között!"
        echo "  Elvárt ($exp_file):"
        xxd "$exp_file"
        echo "  Kapott ($out_file első $exp_size bájt):"
        head -c "$exp_size" "$out_file" | xxd
        set all_ok false
    end

    rm -f "$out_file"
end

echo "----------------------------------------"
if test "$all_ok" = true
    echo "ok"
else
    echo "NEM MINDEN TESZT SIKERES: legalább egy teszteset elbukott."
    exit 1
end
