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
