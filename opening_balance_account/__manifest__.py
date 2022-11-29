# -*- coding: utf-8 -*-
{
    'name': "Opening Balance Account",
    'summary': """
        For Configuring Opening Balance in Chart of Accounts """,
    'description': """
        For Configuring Opening Balance in Chart of Accounts Easily From a Form
    """,

    'author': 'Enzapps Private Limited',
    'company': 'Enzapps Private Limited',
    'maintainer': 'Enzapps Private Limited',
    'live_test_url': '',
    'website': "https://www.enzapps.com",
    'license': 'AGPL-3',
     'images': ['static/description/icon.png'],
    'category': 'Invoicing',
    'version': '14.0',
    'price': 0,
    'currency': 'USD',
    'depends': ['base','account'],
    'data': [
        'security/ir.model.access.csv',
        'views/opening_balance_account.xml',
    ],
}
