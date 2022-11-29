# -*- coding: utf-8 -*-
{
    'name': "KSA Zatca Phase-2",
    'summary': """
        Phase-2 of ZATCA e-Invoicing(Fatoorah): Integration Phase, its include solution for KSA business""",
    'description': """
        Phase-2 of ZATCA e-Invoicing(Fatoorah): Integration Phase, its include solution for KSA business
    """,
    'live_test_url': 'https://youtu.be/QzapL0EcZZk',
    "author": "Alhaditech",
    "website": "www.alhaditech.com",
    'license': 'AGPL-3',
     'images': ['static/description/cover.png'],
    'category': 'Invoicing',
    'version': '14.0',
    'price': 399, 'currency': 'USD',
    'depends': ['account', 'sale', 'l10n_sa_invoice', 'purchase', 'account_debit_note'],
    'external_dependencies': {
        'python': ['cryptography', 'lxml']
    },
    'data': [
        'data/data.xml',
        'views/res_config_settings.xml',
        'views/res_partner.xml',
        'views/res_company.xml',
        'views/account_move.xml',
        'views/account_tax.xml',
        'views/product_product.xml',
    ],
}
