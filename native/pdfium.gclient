solutions = [{
  'name': 'pdfium',
  'url': 'https://pdfium.googlesource.com/pdfium.git@2fd6cff57d9412cc42ef1a7e4e0a59b13a1e7cec',
  'managed': False,
  'custom_deps': {},
  'custom_hooks': [{'name': 'download_and_configure_reclient_cfgs'}, {'name': 'configure_reclient_cfgs'}],
  'custom_vars': {'checkout_configuration': 'minimal', 'checkout_rust': False, 'non_git_source': False},
}]
