import re


def account_type(account):
    if len(account.split('@')) == 1:
        if re.match(r'^\+\d+$', account):
            return 'phone'
        if len(account.split('.')) > 1:
            return 'domain'

    # otherwise the account is in format <username>@<provider>
    name, provider = account.split('@')

    if len(provider.split('.')) > 1:
        # if the provider is something like domain.com
        # then it is a full domain and hence an email
        return 'email'

    # otherwise it is a silo, to which we'll proceed using
    return provider
    # 'github', 'twitter', 'instagram' etc.


def username_valid(user):
    return re.match('^[a-z0-9_]+$', user)
