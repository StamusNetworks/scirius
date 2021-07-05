from webpack_loader.loader import WebpackLoader


class HuntLoader(WebpackLoader):
    def get_assets(self):
        assets = super().get_assets()
        assets['assets'] = {}
        for asset in assets['chunks']['main']:
            assets['assets'][asset['name']] = asset

        assets['chunks']['main'] = list(assets['assets'].keys())
        return assets
