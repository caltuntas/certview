function! g:ToByteArray(decimal)
  let hex=printf("%X",a:decimal)
  let len=len(hex)
  if len % 2 == 1
    let len+=1
  endif
  let hex=printf("%0*X",len,a:decimal)
  let result=substitute(hex, '\w\{2\}', '0x&,', 'g')
  let result = substitute(result, ',$', '', '')
  return result
endfunction

function! g:ReplaceCurrentDecimalWithByteArray()
  let cur_word=expand("<cword>")
  let byte_array=g:ToByteArray(cur_word)
  normal! ciw
  execute "normal! a" . byte_array
endfunction

"'<,'>v/\<test_div_bigint\>\|UNIT/norm I//
"'<,'>g/\/\/RUN/norm _xx
"convert current line containing a binary number to hex
":'<,'>s/^.*$/\=printf("0x%X", "0b" . getline("."))/g | noh
"convert visually selected binary to hex
":'<,'>s/\%V\v(\w+)/\=printf("0x%X", str2nr(submatch(1), 2))/g
":'<,'>s/\%V\v(\w+)/\=printf("0x%X","0b" . submatch(1))/g
