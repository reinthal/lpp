import dash_core_components as dcc
import dash_html_components as html
import dash_bootstrap_components as dbc
from dash.dependencies import Input, Output

from app import app
from apps import analyze, overview


navbar = dbc.NavbarSimple(
                children=[
                    dbc.NavLink("Analyze", id='Analyze', href='/analyze'),
                    dbc.NavLink("Overview", id='Overview', href='/overview'),
                ]
                ,
                brand="l++ 🐨",
                brand_href="https://c.xkcd.com/random/comic/",
            )

app.layout = html.Div(
    [
        dbc.Row(dbc.Col(navbar)), 
        dcc.Location(refresh=False, id='url'),
        dbc.Row([
            dbc.Col(html.Div(id="left-border"), width=1),
            dbc.Col(html.Div(id='page-content'), width=8),
            dbc.Col(html.Div(id="right-border"), width=1)
        ])
        
    ]
)


@app.callback(Output('page-content', 'children'),
              [Input('url', 'pathname')])
def display_page(pathname):
    if pathname:
        if pathname == "/":
            return ""
        elif pathname.startswith("/analyze"):
            return analyze.layout
        elif pathname.startswith("/overview"):
            return overview.layout
        else:
            return '404'

if __name__ == '__main__':
    app.run_server(debug=True, host="0.0.0.0")