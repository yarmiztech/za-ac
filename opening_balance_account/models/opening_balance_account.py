from odoo import fields, models
from odoo.exceptions import UserError
import xlrd


class OpeningBalanceAccountForm(models.Model):
    _name = 'opening.balance.account.form'
    _rec_name = 'date'

    def _default_account_id(self):
        account = self.env['account.account'].search(
            [('company_id', '=', self.env.company.id), ('name', '=', 'Undistributed Profits/Losses')])
        account_id = None
        if account:
            account_id = account[-1].id
        return account_id

    date = fields.Date()
    account_id = fields.Many2one('account.account', default=_default_account_id)
    state = fields.Selection([('draft', 'Draft'), ('post', 'Post')], default='draft')
    open_account_lines = fields.One2many('opening.balance.account.form.lines', 'opening_id')
    journal_id = fields.Many2one('account.move')
    company_id = fields.Many2one('res.company', string='Company', index=True, default=lambda self: self.env.company.id)

    def post(self):
        account_list = []
        journal_id = self.env['account.journal'].search(
            [('name', '=', 'Miscellaneous Operations'), ('company_id', '=', self.env.user.company_id.id)]).id
        credit = sum(self.open_account_lines.mapped('credit'))
        debit = sum(self.open_account_lines.mapped('debit'))
        if credit != debit:
            if credit > debit:
                if self.account_id:
                    account_list.append((0, 0, {
                        'account_id': self.account_id.id,
                        'debit': credit - debit,
                    }))
                else:
                    raise UserError('Please Provide The Account For Debit')
            if debit > credit:
                if self.account_id:
                    account_list.append((0, 0, {
                        'account_id': self.account_id.id,
                        'credit': debit - credit,
                    }))
                else:
                    raise UserError('Please Provide The Account For Credit')

        for account in self.open_account_lines:
            if account.credit > 0:
                account_line = (0, 0, {
                    'account_id': account.account_id.id,
                    'credit': account.credit,
                })
                account_list.append(account_line)
            if account.debit > 0:
                account_line = (0, 0, {
                    'account_id': account.account_id.id,
                    'debit': account.debit,
                })
                account_list.append(account_line)

        if credit > 0 or debit > 0:
            self.journal_id = self.env['account.move'].create({
                'date': self.date,
                'ref': 'Opening Balance',
                'journal_id': journal_id,
                'line_ids': account_list,
            }).id
            self.journal_id.action_post()
            self.state = "post"


class OpeningBalanceAccountLines(models.Model):
    _name = 'opening.balance.account.form.lines'

    opening_id = fields.Many2one('opening.balance.account.form')
    account_id = fields.Many2one('account.account')
    debit = fields.Float()
    credit = fields.Float()
