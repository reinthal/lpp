import dash
import dash_bootstrap_components as dbc
external_stylesheets = [dbc.themes.BOOTSTRAP]

app = dash.Dash(__name__, suppress_callback_exceptions=True, external_stylesheets=external_stylesheets, prevent_initial_callbacks=True)
server = app.server